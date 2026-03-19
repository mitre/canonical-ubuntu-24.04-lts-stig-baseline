control 'SV-270789' do
  title 'Ubuntu 24.04 LTS must generate audit records for successful/unsuccessful uses of the sudoedit command.'
  desc 'Without generating audit records specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter).'
  desc 'check', 'Verify Ubuntu 24.04 LTS generates an audit record upon successful/unsuccessful attempts to use the "sudoedit" command with the following command:

$ sudo auditctl -l | grep /usr/bin/sudoedit
-a always,exit -F path=/usr/bin/sudoedit -F perm=x -F auid>=1000 -F auid!=-1 -k priv_cmd

If the command does not return a line that matches the example or the line is commented out, this is a finding.

Note: The "-k" allows for specifying an arbitrary identifier, and the string after it does not need to match the example output above.'
  desc 'fix', 'Configure the audit system to generate an audit event for any successful/unsuccessful use of the "sudoedit" command.

Add or update the following rules in the "/etc/audit/rules.d/stig.rules":

-a always,exit -F path=/usr/bin/sudoedit -F perm=x -F auid>=1000 -F auid!=-1 -k priv_cmd

To reload the rules file, issue the following command:

$ sudo augenrules --load'
  impact 0.5
  tag check_id: 'C-74822r1066854_chk'
  tag severity: 'medium'
  tag gid: 'V-270789'
  tag rid: 'SV-270789r1066856_rule'
  tag stig_id: 'UBTU-24-900180'
  tag gtitle: 'SRG-OS-000064-GPOS-00033'
  tag fix_id: 'F-74723r1066855_fix'
  tag satisfies: ['SRG-OS-000037-GPOS-00015', 'SRG-OS-000042-GPOS-00020', 'SRG-OS-000062-GPOS-00031', 'SRG-OS-000392-GPOS-00172', 'SRG-OS-000462-GPOS-00206', 'SRG-OS-000471-GPOS-00215']
  tag 'documentable'
  tag cci: ['CCI-000130', 'CCI-000135', 'CCI-000169', 'CCI-000172', 'CCI-002884']
  tag nist: ['AU-3 a', 'AU-3 (1)', 'AU-12 a', 'AU-12 c', 'MA-4 (1) (a)']
  tag 'host'

  audit_command = '/usr/bin/sudoedit'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }

  describe 'Command' do
    it "#{audit_command} is audited properly" do
      audit_rule = auditd.file(audit_command)
      expect(audit_rule).to exist
      expect(audit_rule.action.uniq).to cmp 'always'
      expect(audit_rule.list.uniq).to cmp 'exit'
      expect(audit_rule.fields.flatten).to include('perm=x', 'auid>=1000', 'auid!=-1')
      expect(audit_rule.key.uniq).to include(input('audit_rule_keynames').merge(input('audit_rule_keynames_overrides'))[audit_command])
    end
  end
end
