# https://www.densify.com/articles/deploy-minishift-public-cloud
import argparse
import boto3
import botocore
from datetime import datetime
import json
import logging
import os
from paramiko import SSHClient, AutoAddPolicy
from pathlib import Path
from random import randint
from time import time

HOME = str(Path.home())
RANDOM = str(randint(0, 9999))
DESCRIPTION = """
This script helps to spin up an Openshift lab and gitlab eventually.
The CloudFormation template will spin up two EC2 instances for setting up minishift.
It also schedule automatic deletion of CloudFormation stacks.
""".strip()
PROMETHEUS = """
[Unit]
Description=Prometheus
Wants=network-online.target
After=network-online.target
[Service]
User=prometheus
Group=prometheus
Type=simple
ExecStart=/usr/local/bin/prometheus \
    --config.file /etc/prometheus/prometheus.yml \
    --storage.tsdb.path /var/lib/prometheus/ \
    --web.console.templates=/etc/prometheus/consoles \
    --web.console.libraries=/etc/prometheus/console_libraries
[Install]
WantedBy=multi-user.target'
""".strip()

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
    }
    for arg in args['deploy']:
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
        dest='deploy', default=['minishift', 'gitlab', 'prometheus'],
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
    cf = boto3.client('cloudformation', region_name=args['region'])
    logging.getLogger('deploy.cf.create_or_update')
    template_data = _parse_template(args['file'], cf)
    stack_name = args['stack']
    parameter_data = [
        {
            'ParameterKey': 'KeyName',
            'ParameterValue': os.path.basename(args['key']).replace('.pem', '')
        },
        {
            'ParameterKey': 'StackName',
            'ParameterValue': stack_name
        },
        {
            'ParameterKey': 'TTL',
            'ParameterValue': str(args['ttl'])
        },
    ]
    for arg in args['deploy']:
        parameter_data.append({
            'ParameterKey': arg.capitalize(),
            'ParameterValue': "true"
        })
    params = {
        'StackName': stack_name, 'TemplateBody': template_data,
        'Parameters': parameter_data, 'Capabilities': ['CAPABILITY_IAM']
    }

    try:
        if _stack_exists(stack_name, cf):
            print('Updating {}'.format(stack_name))
            stack_result = cf.update_stack(**params)
            waiter = cf.get_waiter('stack_update_complete')
        else:
            print('Creating {}'.format(stack_name))
            stack_result = cf.create_stack(**params)
            waiter = cf.get_waiter('stack_create_complete')
        print("...waiting for stack to be ready...")
        waiter.wait(StackName=stack_name)
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
    before = time()
    print(f'STDIN: {command}')
    # Run a command (execute ssh-keygen)
    stdin, stdout, stderr = control.exec_command(command)
    output = stdout.read().decode("utf8")
    error = stderr.read().decode("utf8")
    exit = stdout.channel.recv_exit_status()

    # Print output of command. Will wait for command to finish.
    print(f'STDOUT: {output}')
    print(f'STDERR: {error}')
    # Get return code from command (0 is default for success)
    print(f'Return code: {exit}')
    time_spent = time() - before
    print(f"Time spent between commands: {time_spent:.2f} seconds\n\n")

    # Because they are file objects, they need to be closed
    stdin.close()
    stdout.close()
    stderr.close()
    return [output, error, exit]

def _minishift_shell(control_node_ip, minishift_ip, key):
    # SSH into minishift instances
    control_cli = _connect(control_node_ip, 'ec2-user', key)
    minishift = _connect(minishift_ip, 'centos', key)

    # Minishift Setup
    _command(control_cli, fr'ssh-keygen -b 2048 -t rsa -f /home/ec2-user/.ssh/id_rsa_{RANDOM} -q -N ""')
    id_rsa = _command(control_cli, fr'cat /home/ec2-user/.ssh/id_rsa_{RANDOM}.pub')[0]
    _command(
        minishift,
        r"echo -e 'PubkeyAuthentication yes \nPermitRootLogin yes' | sudo tee -a /etc/ssh/sshd_config"
    )
    _command(minishift, r'sudo systemctl restart sshd')
    _command(
        minishift,
        fr"echo -e '{id_rsa}' | sudo tee -a /root/.ssh/authorized_keys"
    )
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

def _gitlab_shell(gitlab_ip, key):
    # Gitlab Setup
    gitlab = _connect(gitlab_ip, 'ec2-user', key)

    # Gitlab shell scripts
    yum = _command(gitlab, r'ps aux | grep yum')[0].split()[1]
    _command(gitlab, fr'sudo kill -9 {yum}')
    _command(
        gitlab,
        r'sudo yum install -y curl policycoreutils-python openssh-server perl firewalld postfix'
    )
    _command(gitlab, r'sudo systemctl enable sshd')
    _command(gitlab, r'sudo systemctl start sshd')
    _command(gitlab, r'sudo systemctl enable firewalld')
    _command(gitlab, r'sudo systemctl start firewalld')
    _command(gitlab, r'sudo firewall-cmd --permanent --add-service=http')
    _command(gitlab, r'sudo firewall-cmd --permanent --add-service=https')
    _command(gitlab, r'sudo systemctl reload firewalld')
    _command(gitlab, r'sudo systemctl enable postfix')
    _command(gitlab, r'sudo systemctl start postfix')
    _command(
        gitlab,
        r'curl https://packages.gitlab.com/install/repositories/gitlab/gitlab-ee/script.rpm.sh | sudo bash'
    )
    _command(gitlab, fr'sudo EXTERNAL_URL="https://{gitlab_ip}" yum install -y gitlab-ee')

    # Close the gitlab ssh session
    gitlab.close()

def _prometheus_shell(prometheus_ip, key):
    # Prometheus Setup
    prometheus = _connect(prometheus_ip, 'ec2-user', key)

    # prometheus shell scripts
    v = "2.24.1"
    _command(
        prometheus,
        fr'wget https://github.com/prometheus/prometheus/releases/download/v{v}/prometheus-{v}.linux-amd64.tar.gz'
    )
    _command(prometheus, fr'tar -xzvf prometheus-{v}.linux-amd64.tar.gz')
    _command(prometheus, fr'cd prometheus-{v}.linux-amd64/')

    # create user
    _command(prometheus, r'useradd --no-create-home --shell /bin/false prometheus')
    # create directories
    _command(prometheus, r'mkdir -p /etc/prometheus')
    _command(prometheus, r'mkdir -p /var/lib/prometheus')
    # set ownership
    _command(prometheus, r'chown prometheus:prometheus /etc/prometheus')
    _command(prometheus, r'chown prometheus:prometheus /var/lib/prometheus')
    # copy binaries
    _command(prometheus, r'cp prometheus /usr/local/bin/')
    _command(prometheus, r'cp promtool /usr/local/bin/')
    _command(prometheus, r'chown prometheus:prometheus /usr/local/bin/prometheus')
    _command(prometheus, r'chown prometheus:prometheus /usr/local/bin/promtool')
    # copy config
    _command(prometheus, r'cp -r consoles /etc/prometheus')
    _command(prometheus, r'cp -r console_libraries /etc/prometheus')
    _command(prometheus, r'cp prometheus.yml /etc/prometheus/prometheus.yml')
    _command(prometheus, r'chown -R prometheus:prometheus /etc/prometheus/consoles')
    _command(prometheus, r'chown -R prometheus:prometheus /etc/prometheus/console_libraries')

    # setup systemd
    _command(prometheus, fr"echo '{PROMETHEUS}' > /etc/systemd/system/prometheus.service")
    _command(prometheus, r'systemctl daemon-reload')
    _command(prometheus, r'systemctl enable prometheus')
    _command(prometheus, r'systemctl start prometheus')

    # Close the prometheus ssh session
    prometheus.close()

if __name__ == "__main__":
    main()
