'use strict';

/* 
This is for matching syslog output from VMWare servers.

Assumptions:
 * It's already had the syslog priority header stripped off the front.

Need to match lines that look like:
 
2014-03-14T16:12:56.460Z hypervisor04.acceleration.net Hostd: [FFD205B0 verbose 'Snmpsvc.env'] GenerateVarbinds skipping property name='SequenceContext', value='', no oid info from class def keys:(IndicationTime, )

2014-03-14T16:22:52.801Z hypervisor01.acceleration.net vmkernel: cpu3:32800)ScsiDeviceIO: 2337: Cmd(0x412fc26ed2c0) 0x1a, CmdSN 0x3dc65a from world 0 to dev "mpx.vmhba1:C0:T0:L0" failed H:0x0 D:0x2 P:0x0 Valid sense data: 0x5 0x20 0x0.
2014-03-14T16:22:52.801Z hypervisor01.acceleration.net vmkernel: cpu3:32800)NMP: nmp_ThrottleLogForDevice:2321: Cmd 0x1a (0x412fc26ed2c0, 0) to dev "mpx.vmhba1:C0:T0:L0" on path "vmhba1:C0:T0:L0" Failed: H:0x0 D:0x2 P:0x0 Valid sense data: 0x5 0x20 0x0. Act:NONE
2014-03-14T16:18:48.559Z hypervisor02.acceleration.net vmkernel: cpu7:32796)NMP: nmp_ThrottleLogForDevice:2321: Cmd 0x1a (0x412e807b1ec0, 0) to dev "mpx.vmhba0:C0:T0:L0" on path "vmhba0:C0:T0:L0" Failed: H:0x0 D:0x2 P:0x0 Valid sense data: 0x5 0x20 0x0. Act:NONE

2014-03-14T16:17:31Z hypervisor04.acceleration.net sshd[889284]: pam_per_user: create_subrequest_handle(): doing map lookup for user "root"

Section for VMware ESX,  hypervisor02.acceleration.net hostd-probe: id=31541075, version=5.5.0, build=1331820, option=Release
*/

var base_filter = require('../lib/base_filter'),
    util = require('util'),
    moment = require('moment'),
    logger = require('log4node');

function FilterSyslogVMWare() {
  base_filter.BaseFilter.call(this);
  this.mergeConfig({
    name: 'SyslogVMWare'
  });
}
util.inherits(FilterSyslogVMWare, base_filter.BaseFilter);

var base_regex = /^(\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\S*) (\S+) ([^:\[]+)\[?(\d+)?\]?:\s(.*)$/;
FilterSyslogVMWare.prototype.process = function(data) {
  var match = base_regex.exec(data.message);
  if(match) {

    data.original = data.message;
    data['@timestamp'] = moment(match[1],'YYYY-MM-DDTHH:mm:ss.SSSZZ')
      .format('YYYY-MM-DDTHH:mm:ss.SSSZZ');
    data.hostname = match[2].split('.')[0];
    data.syslog_program = match[3];
    if(match[4]){ data.syslog_pid = match[4]; }  //not everything has a pid
    data.message = match[5];

    if(!data.syslog_pid) {
      // [FFD205B0 verbose 'Snmpsvc.env'] GenerateVarbinds skipping property name='SequenceContext', value='', no oid info from class def keys:(IndicationTime, )
      match = data.message.match(/^\[(\S+) (\S+) '([^']+)'\] (.*)/);
      if(match) {
        data.hex = match[1];
        data.level = match[2];
        data.logger = match[3];
        data.message = match[4];
      }
    }
  }
  return data;
};

exports.create = function() {
  return new FilterSyslogVMWare();
};
