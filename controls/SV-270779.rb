control 'SV-270779' do
  title 'Ubuntu 24.04 LTS must generate audit records for successful/unsuccessful uses of the chfn command.'
  desc 'Without generating audit records specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter).'
  desc 'check', 'Verify Ubuntu 24.04 LTS generates audit records upon successful/unsuccessful attempts to use the "chfn" command with the following command:

$ sudo auditctl -l | grep /usr/bin/chfn
-a always,exit -F path=/usr/bin/chfn -F perm=x -F auid>=1000 -F auid!=-1 -k privileged-chfn

If the command does not return lines that match the example or the lines are commented out, this is a finding.

Note: The "-k" allows for specifying an arbitrary identifier, and the string after it does not need to match the example output above.'
  desc 'fix', 'Configure the audit system to generate an audit event for any successful/unsuccessful uses of the "chfn" command.

Add or update the following rules in the "/etc/audit/rules.d/stig.rules" file:

-a always,exit -F path=/usr/bin/chfn -F perm=x -F auid>=1000 -F auid!=-1 -k privileged-chfn

To reload the rules file, issue the following command:

$ sudo augenrules --load'
  impact 0.5
  tag check_id: 'C-74812r1066824_chk'
  tag severity: 'medium'
  tag gid: 'V-270779'
  tag rid: 'SV-270779r1066826_rule'
  tag stig_id: 'UBTU-24-900080'
  tag gtitle: 'SRG-OS-000064-GPOS-00033'
  tag fix_id: 'F-74713r1066825_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }

  audit_file = '/usr/bin/chfn'

  if auditd.lines.nil? || auditd.lines.empty?
    describe 'Audit rules' do
      it 'should have audit rules loaded and auditd configured' do
        expect(auditd.lines).not_to be_nil, 'auditd is not configured or not available'
        expect(auditd.lines).not_to be_empty, 'auditd is configured but no audit rules are loaded'
      end
    end
  else
    describe auditd.file(audit_file) do
      it { should exist }
      its('action') { should_not include 'never' }
      its('permissions.flatten') { should include 'x' }
      its('action.uniq') { should eq ['always'] }
      its('list.uniq') { should eq ['exit'] }
    end
  end
end
