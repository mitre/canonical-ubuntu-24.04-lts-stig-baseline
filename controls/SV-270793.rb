control 'SV-270793' do
  title 'Ubuntu 24.04 LTS must generate audit records for successful/unsuccessful uses of the apparmor_parser command.'
  desc 'Without generating audit records specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter).'
  desc 'check', 'Verify Ubuntu 24.04 LTS generates an audit record upon successful/unsuccessful attempts to use the "apparmor_parser" command with the following command: 
 
$ sudo auditctl -l | grep apparmor_parser
-a always,exit -F path=/sbin/apparmor_parser -F perm=x -F auid>=1000 -F auid!=-1 -k perm_chng 
 
If the command does not return a line that matches the example or the line is commented out, this is a finding. 
 
Note: The "-k" allows for specifying an arbitrary identifier, and the string after it does not need to match the example output above.'
  desc 'fix', 'Configure the audit system to generate an audit event for any successful/unsuccessful use of the "apparmor_parser" command.  
 
Add or update the following rules in the "/etc/audit/rules.d/stig.rules" file: 
 
-a always,exit -F path=/sbin/apparmor_parser -F perm=x -F auid>=1000 -F auid!=-1 -k perm_chng 
   
To reload the rules file, issue the following command: 
 
$ sudo augenrules --load'
  impact 0.5
  tag check_id: 'C-74826r1066866_chk'
  tag severity: 'medium'
  tag gid: 'V-270793'
  tag rid: 'SV-270793r1066868_rule'
  tag stig_id: 'UBTU-24-900220'
  tag gtitle: 'SRG-OS-000064-GPOS-00033'
  tag fix_id: 'F-74727r1066867_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }

  audit_file = '/sbin/apparmor_parser'

  if auditd.lines.nil? || auditd.lines.empty?
    describe 'Audit rules' do
      skip 'No audit rules loaded or auditd not configured'
    end
  else
    describe auditd.file(audit_file) do
      it { should exist }
      its('action') { should_not include 'never' }
      its('permissions.flatten') { should include 'x' }
    end
  end
end
