control 'SV-270765' do
  title 'Ubuntu 24.04 LTS must configure the /var/log directory to be group-owned by syslog.'
  desc "Only authorized personnel are to be made aware of errors and the details of the errors. Error messages are an indicator of an organization's operational state or can identify Ubuntu 24.04 LTS or platform. Additionally, Personally Identifiable Information (PII) and operational information must not be revealed through error messages to unauthorized personnel or their designated representatives. 
 
The structure and content of error messages must be carefully considered by the organization and development team. The extent to which the information system is able to identify and handle error conditions is guided by organizational policy and operational requirements."
  desc 'check', 'Verify that Ubuntu 24.04 LTS configures the /var/log directory to be group-owned by "syslog" with the following command: 
 
$ stat -c "%n %G" /var/log
/var/log syslog 
 
If the "/var/log" directory is not group-owned by syslog, this is a finding.'
  desc 'fix', 'Configure Ubuntu 24.04 LTS to have syslog group-own the /var/log directory with the following command: 
 
$ sudo chgrp syslog /var/log'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000206-GPOS-00084'
  tag gid: 'V-270765'
  tag rid: 'SV-270765r1066784_rule'
  tag stig_id: 'UBTU-24-700100'
  tag fix_id: 'F-74699r1066783_fix'
  tag cci: ['CCI-001314']
  tag nist: ['SI-11 b']
  tag 'host'
  tag 'container'

  describe directory('/var/log') do
    it { should exist }
    its('group') { should eq 'syslog' }
  end
end
