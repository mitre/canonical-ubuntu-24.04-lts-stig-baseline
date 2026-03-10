control 'SV-270703' do
  title 'Ubuntu 24.04 LTS must have system commands group-owned by root or a system account.'
  desc 'If Ubuntu 24.04 LTS were to allow any user to make changes to software libraries, then those changes might be implemented without undergoing the appropriate testing and approvals that are part of a robust change management process. 
 
This requirement applies to Ubuntu 24.04 LTS with software libraries that are accessible and configurable, as in the case of interpreted languages. Software libraries also include privileged programs that execute with escalated privileges. Only qualified and authorized individuals must be allowed to obtain access to information system components for purposes of initiating changes, including upgrades and modifications.'
  desc 'check', %q(Verify the system commands contained in the following directories are group-owned by root or a required system account with the following command: 
 
$ find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin \-type f -perm -u=x -exec stat --format="%n %G" {} + |  \awk '$2 != "root" && $2 != "daemon" && $2 != "adm" && $2 != "shadow" && $2 != "mail" && $2 != "crontab" && $2 != "_ssh"'

Note: The above command uses awk to filter out common system accounts. If your system uses other required system accounts, add them to the awk condition to filter them out of the results.

If any system commands are returned that are not group-owned by a required system account, this is a finding.)
  desc 'fix', 'Configure the system commands to be protected from unauthorized access. Run the following command, replacing "[FILE]" with any system command file not group-owned by "root" or a required system account: 
 
$ sudo chgrp [SYSTEMACCOUNT] [FILE]'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag gid: 'V-270703'
  tag rid: 'SV-270703r1066598_rule'
  tag stig_id: 'UBTU-24-300013'
  tag fix_id: 'F-74637r1066597_fix'
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
  tag 'host'
  tag 'container'

  failing_files = command("find -L #{input('system_command_dirs').join(' ')} -type f ! -group root ! -perm /2000 -exec ls -d {} \\;").stdout.split("\n")

  describe 'System commands' do
    it 'should be group-owned by root' do
      expect(failing_files).to be_empty, "Files not group-owned by root:\n\t- #{failing_files.join("\n\t- ")}"
    end
  end
end
