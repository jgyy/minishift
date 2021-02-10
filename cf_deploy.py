# https://www.densify.com/articles/deploy-minishift-public-cloud
import argparse
import boto3
import botocore
from datetime import datetime
from dotenv import load_dotenv
import json
import logging
import os
from paramiko import SSHClient, AutoAddPolicy
from pathlib import Path
from random import randint
import sys
from time import time

load_dotenv()
HOME = str(Path.home())
RANDOM = str(randint(0, 9999))
REGION = 'ap-southeast-1'
STACK_NAME = ''
DESCRIPTION = """
This script helps to spin up an Openshift lab and gitlab eventually.
The CloudFormation template will spin up two EC2 instances for setting up minishift.
It also schedule automatic deletion of CloudFormation stacks.
""".strip()
with open("alert_manager_service.txt") as file:
    ALERT_MANAGER_SERVICE = file.read()
with open("alert_manager_yml.txt") as file:
    ALERT_MANAGER_YML = file.read().format(
        email=os.getenv('email'),
        password=os.getenv('password'),
        slack=os.getenv('slack')
    )
with open("alert_rules.txt") as file:
    ALERT_RULES = file.read()
with open("grafana.txt") as file:
    GRAFANA = file.read()
with open("node_exporter.txt") as file:
    NODE_EXPORTER = file.read()
with open("prometheus.txt") as file:
    PROMETHEUS = file.read()
NODE_EXPORTER_CONFIG = """
  - job_name: "node_exporter"
    scrape_interval: "5s"
    static_configs:
      - targets:
        - "localhost:9100"
"""[1:-1]

def main():
    """Update or create cloudformation stack"""
    args = _arguments()
    print(args)

    stack = _cloudformation(args)
    print(json.dumps(stack, indent=2, default=json_serial))
    outputs = stack['Stacks'][0]['Outputs']
    # {'ControlNodeIP': '', 'MinishiftIP': '', 'GitlabIP': '', 'PrometheusIP': ''}
    output = {out['OutputKey']: out['OutputValue'] for out in outputs}
    print(output)

    functions = {
        "gitlab": {
            "function": _gitlab_shell,
            "arguments": (output.get('GitlabIP'), args['key'])
        },
        "minishift": {
            "function": _minishift_shell,
            "arguments": (output.get('ControlNodeIP'), output.get('MinishiftIP'), args['key'])
        },
        "prometheus": {
            "function": _prometheus_shell,
            "arguments": (output.get('PrometheusIP'), args['key'])
        }
    }
    for arg in args['deploy']:
        if functions.get(arg):
            function = functions[arg]['function']
            argument = functions[arg]['arguments']
            function(*argument)

def _arguments():
    parse = argparse.ArgumentParser(description=DESCRIPTION.strip("/n"))
    parse.add_argument(
        '-f', '--file',
        action='store', type=str,
        dest='file', required=True,
        help='file path for the cloudformation script'
    )
    parse.add_argument(
        '-k', '--key',
        action='store', type=str,
        dest='key', required=True,
        help='file path for the PEM key'
    )
    parse.add_argument(
        '-d', '--deploy-list', nargs='+',
        action='store', type=str,
        dest='deploy', choices=['minishift', 'gitlab', 'prometheus'],
        help='list of tools to deploy'
    )
    parse.add_argument(
        '-s', '--stack-name',
        action='store', type=str,
        dest='stack', default=f"default-{RANDOM}",
        help='name of cloudformation stack'
    )
    parse.add_argument(
        '-t', '--time-to-live',
        action='store', type=int,
        dest='ttl', default=240,
        help='time to live for this lab session (minutes)'
    )
    parse.add_argument(
        '-r', '--region',
        action='store', type=str,
        dest='region', default='ap-southeast-1',
        help='specify the aws region to spinup the cluster'
    )
    return vars(parse.parse_args())

def _cloudformation(args):
    global REGION, STACK_NAME
    REGION = args['region']
    cf = boto3.client('cloudformation', region_name=REGION)
    logging.getLogger('deploy.cf.create_or_update')
    template_data = _parse_template(args['file'], cf)
    STACK_NAME = args['stack']
    parameter_data = [
        {
            'ParameterKey': 'KeyName',
            'ParameterValue': os.path.basename(args['key']).replace('.pem', '')
        },
        {
            'ParameterKey': 'StackName',
            'ParameterValue': STACK_NAME
        },
        {
            'ParameterKey': 'TTL',
            'ParameterValue': str(args['ttl'])
        },
    ]
    for arg in args['deploy']:
        parameter_data.append({'ParameterKey': arg.capitalize(), 'ParameterValue': "true"})
    params = {
        'StackName': STACK_NAME, 'TemplateBody': template_data,
        'Parameters': parameter_data, 'Capabilities': ['CAPABILITY_IAM']
    }

    try:
        if _stack_exists(STACK_NAME, cf):
            print('Updating {}'.format(STACK_NAME))
            stack_result = cf.update_stack(**params)
            waiter = cf.get_waiter('stack_update_complete')
        else:
            print('Creating {}'.format(STACK_NAME))
            stack_result = cf.create_stack(**params)
            waiter = cf.get_waiter('stack_create_complete')
        print("...waiting for stack to be ready...")
        waiter.wait(StackName=STACK_NAME)
    except botocore.exceptions.ClientError as ex:
        error_message = ex.response['Error']['Message']
        if error_message == 'No updates are to be performed.':
            print("No changes")
        else:
            raise
    else:
        return cf.describe_stacks(StackName=stack_result['StackId'])

def _parse_template(template, cf):
    with open(template) as template_fileobj:
        template_data = template_fileobj.read()
    cf.validate_template(TemplateBody=template_data)
    return template_data

def _stack_exists(stack_name, cf):
    for stack in cf.list_stacks()['StackSummaries']:
        if stack['StackStatus'] == 'DELETE_COMPLETE':
            continue
        if stack_name == stack['StackName']:
            return True
    return False

def json_serial(obj):
    """JSON serializer for objects not serializable by default json code"""
    if isinstance(obj, datetime):
        return obj.isoformat()
    raise TypeError("Type not serializable")

def _connect(domain, user, key):
    """Connect to remote host"""
    control = SSHClient()
    control.load_system_host_keys()
    control.load_host_keys(f'{HOME}\\.ssh\\known_hosts')
    control.set_missing_host_key_policy(AutoAddPolicy())
    control.connect(domain, username=user, key_filename=key)
    return control

def _command(control, command):
    global REGION, STACK_NAME
    before = time()
    print(f'STDIN: {command}')
    # Run a command (execute ssh-keygen)
    stdin, stdout, stderr = control.exec_command(command)
    output = stdout.read().decode("utf8")
    error = stderr.read().decode("utf8")
    exit = stdout.channel.recv_exit_status()

    # Because they are file objects, they need to be closed
    stdin.close()
    stdout.close()
    stderr.close()
    if int(exit) != 0 and 'sudo' not in command:
        return _command(control, fr"sudo {command}")

    # Print output of command. Will wait for command to finish.
    print(f'STDOUT: {output}')
    print(f'STDERR: {error}')
    # Get return code from command (0 is default for success)
    print(f'Return code: {exit}')
    time_spent = time() - before
    print(f"Time spent between commands: {time_spent:.2f} seconds\n\n")

    # Automate deletion of script if error encounted.
    if int(exit) != 0 and 'sudo' in command:
        print('Error encountered while provisioning instance, proceed to delete cloudformation stack!')
        aws_lambda = boto3.client('lambda', region_name=REGION)
        aws_lambda.invoke(FunctionName=f'DeleteCFNLambda-{STACK_NAME}')
        sys.exit("Cloudformation stack delete initiated, exiting the script now!")

    return [output, error, exit]

def _minishift_shell(control_node_ip, minishift_ip, key):
    # SSH into minishift instances
    control_cli = _connect(control_node_ip, 'ec2-user', key)
    minishift = _connect(minishift_ip, 'centos', key)

    # Minishift Setup
    _command(control_cli, fr'ssh-keygen -b 2048 -t rsa -f /home/ec2-user/.ssh/id_rsa_{RANDOM} -q -N ""')
    id_rsa = _command(control_cli, fr'cat /home/ec2-user/.ssh/id_rsa_{RANDOM}.pub')[0]
    _command(minishift, r"echo -e 'PubkeyAuthentication yes \nPermitRootLogin yes' | sudo tee -a /etc/ssh/sshd_config")
    _command(minishift, r'sudo systemctl restart sshd')
    _command(minishift, fr"echo -e '{id_rsa}' | sudo tee -a /root/.ssh/authorized_keys")
    minishift.close()

    # Control Node Setup
    _command(
        control_cli,
        r'wget https://github.com/minishift/minishift/releases/download/v1.34.3/minishift-1.34.3-linux-amd64.tgz'
    )
    _command(control_cli, r'tar zxvf minishift-1.34.3-linux-amd64.tgz')
    _command(control_cli, r'mv minishift-1.34.3-linux-amd64 minishift')
    _command(control_cli, r'rm minishift-1.34.3-linux-amd64.tgz')
    _command(control_cli, r'sudo cp /home/ec2-user/minishift/minishift /usr/bin/minishift')
    _command(control_cli, r'minishift config set vm-driver generic')
    _command(control_cli, r'minishift config view')
    _command(
        control_cli,
        fr'minishift start --remote-ipaddress {minishift_ip} --remote-ssh-user root --remote-ssh-key /home/ec2-user/.ssh/id_rsa_{RANDOM}'
    )
    _command(control_cli, r'minishift status')
    _command(control_cli, r'sudo cp /home/ec2-user/.minishift/cache/oc/v3.11.0/linux/oc /usr/bin/oc')
    _command(control_cli, r'oc status')

    # Close the control node client
    control_cli.close()
    print(fr'http://{minishift_ip}:8443/console/')

def _gitlab_shell(gitlab_ip, key):
    # Gitlab Setup
    gitlab = _connect(gitlab_ip, 'ec2-user', key)

    # Gitlab shell scripts
    _command(gitlab, r'yum install -y curl policycoreutils-python openssh-server perl firewalld postfix')
    _command(gitlab, r'systemctl enable sshd')
    _command(gitlab, r'systemctl start sshd')
    _command(gitlab, r'systemctl enable firewalld')
    _command(gitlab, r'systemctl start firewalld')
    _command(gitlab, r'firewall-cmd --permanent --add-service=http')
    _command(gitlab, r'firewall-cmd --permanent --add-service=https')
    _command(gitlab, r'systemctl reload firewalld')
    _command(gitlab, r'systemctl enable postfix')
    _command(gitlab, r'systemctl start postfix')
    _command(gitlab, r'curl https://packages.gitlab.com/install/repositories/gitlab/gitlab-ee/script.rpm.sh | sudo bash')
    _command(gitlab, fr'EXTERNAL_URL="https://{gitlab_ip}" yum install -y gitlab-ee')

    # Close the gitlab ssh session
    gitlab.close()

def _prometheus_shell(prometheus_ip, key):
    # Prometheus Setup and versions
    prometheus = _connect(prometheus_ip, 'ec2-user', key)

    # prometheus bash commands part 1
    prometheus_version = "2.24.1"
    prometheus_dir = fr"/home/ec2-user/prometheus-{prometheus_version}.linux-amd64"
    _command(
        prometheus,
        fr'wget https://github.com/prometheus/prometheus/releases/download/v{prometheus_version}/prometheus-{prometheus_version}.linux-amd64.tar.gz'
    )
    _command(prometheus, fr'tar -xzvf prometheus-{prometheus_version}.linux-amd64.tar.gz')
    _command(prometheus, fr'cd {prometheus_dir}/')
    # create user
    _command(prometheus, r'useradd --no-create-home --shell /bin/false prometheus')
    # create directories
    _command(prometheus, r'mkdir -p /etc/prometheus')
    _command(prometheus, r'mkdir -p /var/lib/prometheus')
    # set ownership
    _command(prometheus, r'chown prometheus:prometheus /etc/prometheus')
    _command(prometheus, r'chown prometheus:prometheus /var/lib/prometheus')
    # copy binaries
    _command(prometheus, fr'cp {prometheus_dir}/prometheus /usr/local/bin/prometheus')
    _command(prometheus, fr'cp {prometheus_dir}/promtool /usr/local/bin/promtool')
    _command(prometheus, r'chown prometheus:prometheus /usr/local/bin/prometheus')
    _command(prometheus, r'chown prometheus:prometheus /usr/local/bin/promtool')
    # copy config
    _command(prometheus, fr'cp -r {prometheus_dir}/consoles /etc/prometheus/consoles')
    _command(prometheus, fr'cp -r {prometheus_dir}/console_libraries /etc/prometheus/console_libraries')
    # edit prometheus yml to be all double quotes in order to avoid syntax error later
    prometheus_yml = _command(prometheus, fr'cat {prometheus_dir}/prometheus.yml')[0].replace('\'', '"')
    _command(prometheus, fr"echo '{prometheus_yml}' | sudo tee /etc/prometheus/prometheus.yml")
    _command(prometheus, r'chown -R prometheus:prometheus /etc/prometheus/consoles')
    _command(prometheus, r'chown -R prometheus:prometheus /etc/prometheus/console_libraries')
    # setup systemd
    _command(prometheus, fr"echo '{PROMETHEUS}' | sudo tee /etc/systemd/system/prometheus.service")
    _command(prometheus, r'systemctl daemon-reload')
    _command(prometheus, r'systemctl enable prometheus')
    _command(prometheus, r'systemctl start prometheus')

    # setup node exporter part 2
    node_exporter_version = '1.0.1'
    node_exporter_dir = fr"/home/ec2-user/node_exporter-{node_exporter_version}.linux-amd64"
    _command(
        prometheus,
        fr"wget https://github.com/prometheus/node_exporter/releases/download/v{node_exporter_version}/node_exporter-{node_exporter_version}.linux-amd64.tar.gz"
    )
    _command(prometheus, fr"tar -xzvf node_exporter-{node_exporter_version}.linux-amd64.tar.gz")
    _command(prometheus, fr"cd {node_exporter_dir}/")
    _command(prometheus, fr"cp {node_exporter_dir}/node_exporter /usr/local/bin/node_exporter")
    # create user
    _command(prometheus, r"useradd --no-create-home --shell /bin/false node_exporter")
    _command(prometheus, r"chown node_exporter:node_exporter /usr/local/bin/node_exporter")
    _command(prometheus, fr"echo '{NODE_EXPORTER}' | sudo tee /etc/systemd/system/node_exporter.service")
    # enable node_Exporter in systemctl
    _command(prometheus, r"systemctl daemon-reload")
    _command(prometheus, r"systemctl start node_exporter")
    _command(prometheus, r"systemctl enable node_exporter")
    _command(prometheus, fr"echo '{NODE_EXPORTER_CONFIG}' | sudo tee -a /etc/prometheus/prometheus.yml")
    # restart prometheus server
    _command(prometheus, r"service prometheus restart")
    _command(prometheus, r"service prometheus status")

    # setup grafana for redhat part 3
    _command(prometheus, fr"echo '{GRAFANA}' | sudo tee /etc/yum.repos.d/grafana.repo")
    _command(prometheus, r"yum install -y grafana")
    _command(prometheus, r"systemctl daemon-reload")
    _command(prometheus, r"systemctl start grafana-server")
    _command(prometheus, r"systemctl enable grafana-server.service")

    # setup alert manager for part 4
    alert_manager_version = "0.21.0"
    alert_manager_dir = fr"/home/ec2-user/alertmanager-{alert_manager_version}.linux-amd64"
    _command(
        prometheus,
        fr"wget https://github.com/prometheus/alertmanager/releases/download/v{alert_manager_version}/alertmanager-{alert_manager_version}.linux-amd64.tar.gz"
    )
    _command(prometheus, fr"tar -xzvf alertmanager-{alert_manager_version}.linux-amd64.tar.gz")
    _command(prometheus, fr"cd {alert_manager_dir}/")
    # create user
    _command(prometheus, r"useradd --no-create-home --shell /bin/false alertmanager")
    # create directories
    _command(prometheus, r"mkdir /etc/alertmanager")
    _command(prometheus, r"mkdir /etc/alertmanager/template")
    _command(prometheus, r"mkdir -p /var/lib/alertmanager/data")
    # touch config file
    _command(prometheus, r"touch /etc/alertmanager/alertmanager.yml")
    # set ownership
    _command(prometheus, r"chown -R alertmanager:alertmanager /etc/alertmanager")
    _command(prometheus, r"chown -R alertmanager:alertmanager /var/lib/alertmanager")
    # copy binaries
    _command(prometheus, fr"cp {alert_manager_dir}/alertmanager /usr/local/bin/")
    _command(prometheus, fr"cp {alert_manager_dir}/amtool /usr/local/bin/")
    # set ownership
    _command(prometheus, r"chown alertmanager:alertmanager /usr/local/bin/alertmanager")
    _command(prometheus, r"chown alertmanager:alertmanager /usr/local/bin/amtool")
    # setup systemd
    _command(prometheus, fr"echo '{ALERT_MANAGER_SERVICE}' | sudo tee /etc/systemd/system/alertmanager.service")
    _command(prometheus, r'systemctl daemon-reload')
    _command(prometheus, r'systemctl enable alertmanager')
    _command(prometheus, r'systemctl start alertmanager')
    # restart prometheus and update yml file
    _command(prometheus, r'systemctl start prometheus')
    _command(prometheus, r"echo '" + ALERT_MANAGER_YML + r"' | sudo tee /etc/alertmanager/alertmanager.yml")
    _command(prometheus, r"service alertmanager restart")
    _command(prometheus, r"service alertmanager status")
    prometheus_yml = _command(prometheus, r"cat /etc/prometheus/prometheus.yml")[0]
    prometheus_yml = prometheus_yml.replace(r'# - alertmanager:9093', r'- localhost:9093')
    prometheus_yml = prometheus_yml.replace(r'# - "first_rules.yml"', r'- "/etc/prometheus/alert.rules"')
    prometheus_yml = prometheus_yml.replace(r'  # - "second_rules.yml"', "")
    _command(prometheus, fr"echo '{prometheus_yml}' | sudo tee /etc/prometheus/prometheus.yml")
    _command(prometheus, r"echo '" + ALERT_RULES + r"' | sudo tee /etc/prometheus/alert.rules")
    _command(prometheus, r'service prometheus restart')
    _command(prometheus, r'service prometheus status')

    # no mail server, use gmail. Now to introduce stress
    _command(prometheus, r'amazon-linux-extras install epel')
    _command(prometheus, r'yum install stress -y')
    _command(prometheus, r'stress --cpu 1 --io 1 --vm 1 --vm-bytes 128M --timeout 9999s')

    # Close the prometheus ssh session and print out the url
    prometheus.close()
    print(fr'grafana url: http://{prometheus_ip}:3000/')
    print(fr'prometheus url: http://{prometheus_ip}:9090/')
    print(fr'node exporter url: http://{prometheus_ip}:9100/')
    print(fr'alert manager url: http://{prometheus_ip}:9093/')

if __name__ == "__main__":
    main()