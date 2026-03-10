control 'SV-270811' do
  title 'Ubuntu 24.04 LTS must generate audit records for the /var/run/utmp file.'
  desc 'Without generating audit records specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter).'
  desc 'check', %q(Verify Ubuntu 24.04 LTS generates audit records showing start and stop times for user access to the system via the "/var/run/utmp" file with the following command:
 
$ sudo auditctl -l | grep '/var/run/utmp'
-w /var/run/utmp -p wa -k logins 
 
If the command does not return a line matching the example or the line is commented out, this is a finding. 
 
Note: The "-k" allows for specifying an arbitrary identifier, and the string after it does not need to match the example output above.)
  desc 'fix', 'Configure the audit system to generate audit events showing start and stop times for user access via the "/var/run/utmp" file. 
 
Add or update the following rules in the "/etc/audit/rules.d/stig.rules" file: 
 
-w /var/run/utmp -p wa -k logins 
  
To reload the rules file, issue the following command: 
 
$ sudo augenrules --load'
  impact 0.5
  tag check_id: 'C-74844r1066920_chk'
  tag severity: 'medium'
  tag gid: 'V-270811'
  tag rid: 'SV-270811r1066922_rule'
  tag stig_id: 'UBTU-24-900600'
  tag gtitle: 'SRG-OS-000472-GPOS-00217'
  tag fix_id: 'F-74745r1066921_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }

  audit_file = '/var/run/utmp'

  if auditd.lines.nil? || auditd.lines.empty?
    describe 'Audit rules' do
      skip 'No audit rules loaded or auditd not configured'
    end
  else
    describe auditd.file(audit_file) do
      it { should exist }
      its('action') { should_not include 'never' }
      its('permissions.flatten') { should include('w', 'a') }
    end
  end
end
