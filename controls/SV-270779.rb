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

  if virtualization.system.eql?('docker')
    impact 0.0
    describe 'Control not applicable to a container' do
      skip 'Control not applicable to a container'
    end
  else
    @audit_file = '/usr/bin/chfn'

    audit_lines_exist = !auditd.lines.index { |line| line.include?(@audit_file) }.nil?
    if audit_lines_exist
      describe auditd.file(@audit_file) do
        its('permissions') { should_not cmp [] }
        its('action') { should_not include 'never' }
        its('action.uniq') { should eq ['always'] }
        its('list.uniq') { should eq ['exit'] }
      end

      @perms = auditd.file(@audit_file).permissions

      @perms.each do |perm|
        describe perm do
          it { should include 'x' }
        end
      end
    else
      describe('Audit line(s) for ' + @audit_file + ' exist') do
        subject { audit_lines_exist }
        it { should be true }
      end
    end
  end
end
