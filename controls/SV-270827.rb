control 'SV-270827' do
  title 'Ubuntu 24.04 LTS must be configured so that audit log files are not read or write-accessible by unauthorized users.'
  desc 'Unauthorized disclosure of audit records can reveal system and configuration data to attackers, thus compromising its confidentiality.  
  
Audit information includes all information (e.g., audit records, audit settings, audit reports) needed to successfully audit operating system activity.'
  desc 'check', 'Verify that the audit log files have a mode of "0600" or less permissive. 
 
Determine where the audit logs are stored with the following command: 
 
$ sudo grep -iw log_file /etc/audit/auditd.conf
log_file = /var/log/audit/audit.log 
 
Using the path of the directory containing the audit logs, determine if the audit log files have a mode of "0600" or less with the following command: 
 
$ sudo stat -c "%n %a" /var/log/audit/*
/var/log/audit/audit.log 600 
 
If the audit log files have a mode more permissive than "0600", this is a finding.'
  desc 'fix', 'Configure the audit log files to have a mode of "0600" or less permissive. 
 
Determine where the audit logs are stored with the following command: 
 
$ sudo grep -iw log_file /etc/audit/auditd.conf 

log_file = /var/log/audit/audit.log 
 
Using the path of the directory containing the audit logs, configure the audit log files to have a mode of "0600" or less permissive by using the following command: 
 
$ sudo chmod 0600 /var/log/audit/*'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000057-GPOS-00027'
  tag satisfies: ['SRG-OS-000057-GPOS-00027', 'SRG-OS-000058-GPOS-00028', 'SRG-OS-000059-GPOS-00029', 'SRG-OS-000206-GPOS-00084']
  tag gid: 'V-270827'
  tag rid: 'SV-270827r1066970_rule'
  tag stig_id: 'UBTU-24-901300'
  tag fix_id: 'F-74761r1066969_fix'
  tag cci: ['CCI-000162', 'CCI-000163', 'CCI-000164', 'CCI-001314']
  tag nist: ['AU-9', 'AU-9 a', 'SI-11 b']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  log_file = auditd_conf('/etc/audit/auditd.conf').log_file
  describe file(log_file) do
    it { should_not be_more_permissive_than('0600') }
  end
end
