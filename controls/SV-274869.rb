control 'SV-274869' do
  title 'Ubuntu 24.04 LTS must restrict privilege elevation to authorized personnel.'
  desc 'If the "sudoers" file is not configured correctly, any user defined on the system can initiate privileged actions on the target system.'
  desc 'check', "Verify the operating system restricts privilege elevation to authorized personnel with the following command:

$ sudo grep -iwR 'ALL' /etc/sudoers /etc/sudoers.d/ | grep -v '#'

If either of the following entries are returned, this is a finding:
ALL     ALL=(ALL) ALL
ALL     ALL=(ALL:ALL) ALL"
  desc 'fix', 'Configure the operating system to restrict privilege elevation to authorized personnel.

Remove the following entries from the /etc/sudoers file or any configuration file under /etc/sudoers.d/:

ALL     ALL=(ALL) ALL
ALL     ALL=(ALL:ALL) ALL'
  impact 0.5
  tag check_id: 'C-78970r1107311_chk'
  tag severity: 'medium'
  tag gid: 'V-274869'
  tag rid: 'SV-274869r1107312_rule'
  tag stig_id: 'UBTU-24-300019'
  tag gtitle: 'SRG-OS-000373-GPOS-00156'
  tag fix_id: 'F-78875r1101747_fix'
  tag 'documentable'
  tag cci: ['CCI-002038', 'CCI-004895']
  tag nist: ['IA-11', 'SC-11 b']
end
