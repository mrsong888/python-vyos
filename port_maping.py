# !/usr/bin/env python
# *-* coding:utf-8 *-*
import time
import re
import json
from vymgmt import Router, ConfigError

d = {'nat': '''nat destination rule {rule} description 'Port Forward: HTTP to {address}',\
nat destination rule {rule} destination port '{port}',\
nat destination rule {rule} inbound-interface '{inbound_interface}',\
nat destination rule {rule} protocol 'tcp',\
nat destination rule {rule} translation address '{address}' '''}

d2 = {'nat': '''{
         "%(rule)s": {
             "description": "Port Forward: HTTP to %(address)s",
             "destination": {
                 "port": %(port)d
             },
             "inbound-interface": "%(inbound_interface)s",
             "protocol": "tcp",
             "translation": {
                 "address": "%(address)s"
                }
            }
        }'''}

def config_command(**kwargs):
    def finder():
        config_type = kwargs.get('conf_type', None)
        if config_type:
            temp = d[config_type].format(**kwargs)
            return temp.split(',')
        else:
            raise Exception('config type is wrong')
    return finder

def nat_conf_data(target_data):
    temp_dict = {}
    rule_list = []
    port_map = {'nat': {'destination': {}}}
    for index, letter in enumerate(target_data):
        if letter == 'rule':
            temp_dict['rule'] = int(target_data[index+1])
            rule_list.append(int(target_data[index+1]))
        elif letter == 'port':
            temp_dict['port'] = int(target_data[index+1])
        elif letter == 'address':
            temp_dict['address'] = target_data[index+1]
        elif letter == 'inbound-interface':
            temp_dict['inbound_interface'] = target_data[index+1]
        if len(temp_dict) == 4:
            temp = json.loads(d2['nat'] % temp_dict)
            port_map['nat']['destination'].update(temp)
            temp_dict.clear()
    return port_map, rule_list
def firewall_conf_data():
    pass

def policy_conf_data():
    pass


class Failure(Exception):

    def __init__(self, message='', code=None):
        super(Failure, self).__init__(message)
        self.code = code

class Base(object):
    router = Router
    mode_list = ['cluster', 'firewall', 'interfaces', 'nat', 'policy', 'protocols', 'service', 'system',
                 'traffic-policy', 'vpn']
    return_conf_mode_list = ['nat']
    func_to_conf_mode = {'nat': nat_conf_data}
    def __init__(self, conn, **kwargs):
        self.conn = conn
        self.conf_modified = False
        self.conf_type = kwargs.get('conf_type')
        self.rule =  kwargs.get('rule')
        if self.conf_type != 'all' and self.conf_type:
            self.command_list = config_command(**kwargs)()
    @classmethod
    def vyos_login(cls, *args, **kwargs):
        obj = cls.router(*args)
        try:
            obj.login()
        except Exception as e:
            print e
        return cls(obj, **kwargs)
    def __enter__(self):
        return self
    def __exit__(self, exc_tp, exc_val, exc_tb):
        if exc_val and isinstance(exc_val, ConfigError):
            self.exit()
            self.finish()
            if re.search(r"Set\s+failed", exc_val.message):
                raise Failure(message=exc_val.message, code='failed' )
        self.finish()
    def middle_handler(self, conf_type, temp_list):
        temp_dict = {}
        conf_type_index = temp_list.index(conf_type)
        for mode in self.mode_list:
            try:
                index = temp_list.index(mode)
                if mode == 'protocols' and temp_list[index-1] == 'facility':
                    continue
                temp_dict[index] = mode
            except ValueError:
                pass
        key_list = sorted(temp_dict.keys())
        if conf_type_index == key_list[-1]:
            return temp_list[conf_type_index:]
        else:
            index_r = key_list.index(conf_type_index) + 1
            return temp_list[conf_type_index:key_list[index_r]]

    def prepare_before_set(self):
        if self.conf_type in {'nat', 'firewall', 'policy'}:
            _, rule_list = self.get_configuration()
            if self.rule in rule_list:
                raise Failure('rule exist', code='exist')
        self.configure()
    def get_configuration(self):
        self.conn._Router__conn.PROMPT = "\[PEXPECT\][\$\#] "
        res = self.run_no_conf_command('cli-shell-api showCfg').encode('utf-8')
        mid_list = re.split(r'[\r\n|\s]\s*', res)
        if self.conf_type not in mid_list:
            return [],[]
        if self.conf_type == 'all':
            pass
        else:
            result = self.middle_handler(self.conf_type, mid_list)
            # return result
            return self.func_to_conf_mode[self.conf_type](result)
    def configure(self):
        self.conn.configure()

    def commit(self):
        self.conn.commit()
        self.conn.save()
        self.exit()
    def run_no_conf_command(self, command):
        return self.conn.run_op_mode_command(command)
    def set(self):
        self.prepare_before_set()
        for command in self.command_list:
            print command
            self.conn.set(command)
        self.conf_modified = True
        self.commit()

    def delete(self):
        pass
    def exit(self):
        self.conn.exit()
    def finish(self):
        self.conn.logout()
        self.conn = None

class WithRuleDel(Base):

    def __init__(self, conn, conf_type, rule=None):
        self.conn = conn
        self.conf_delete = False
        self.conf_type = conf_type
        self.rule = rule
    def prepare_before_delete(self):
        temp_l, temp_r = self.get_configuration()
        if temp_l:
            if self.rule:
                if self.rule not in temp_r:
                    raise Failure('the special rule not exits')
                else:
                    command = '{conf_type} destination rule {rule}'.format(conf_type=self.conf_type, rule=self.rule)
                    self.configure()
                    return command
            else:
                command = '{conf_type}'.format(conf_type=self.conf_type)
                self.configure()
                return command

        else:
            raise Failure('the specified node does not exist')
    def delete(self):
        command = self.prepare_before_delete()
        self.conn.delete(command)
        self.commit()
        # self.conf_delete = True
        self.confirm_delete()
    def confirm_delete(self):
        temp_l, temp_r = self.get_configuration()
        if temp_l:
            if self.rule:
                if self.rule in temp_r:
                    raise Failure('the config rule delete failed')
                else:
                    self.conf_delete = True
        else:
            self.conf_delete = True

start = time.time()
try:
    with WithRuleDel.vyos_login('101.251.198.244', 'vyos', 'vyos', conf_type='nat', rule=10) as r:
        r.delete()
        print r.get_configuration()
        print r.conf_delete
except Exception as e:
    raise
# print WithRuleDel.__dict__

# with Base.vyos_login('101.251.198.244', 'vyos', 'vyos', conf_type='nat', rule=116, address='192.168.1.1',port=80, inbound_interface='eth0') as r:
#     r.set()
#     print r.get_configuration()
    # print r.get_configuration()
    # print r.get_configuration()
print time.time() - start


