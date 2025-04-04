control 'SV-270712' do
  title 'Ubuntu 24.04 LTS must disable the x86 Ctrl-Alt-Delete key sequence.'
  desc 'A locally logged-on user who presses Ctrl-Alt-Delete, when at the console, can reboot the system. If accidentally pressed, as could happen in the case of a mixed OS environment, this can create the risk of short-term loss of availability of systems due to unintentional reboot.'
  desc 'check', 'Verify Ubuntu 24.04 LTS is not configured to reboot the system when Ctrl-Alt-Delete is pressed with the following command:

$ systemctl status ctrl-alt-del.target
o   ctrl-alt-del.target
     Loaded: masked (Reason: Unit ctrl-alt-del.target is masked.)
     Active: inactive (dead)

If the "ctrl-alt-del.target" is not masked, this is a finding.'
  desc 'fix', 'Configure the system to disable the Ctrl-Alt-Delete sequence for the command line with the following commands:

$ sudo systemctl disable ctrl-alt-del.target
[...]

$ sudo systemctl mask ctrl-alt-del.target
Created symlink /etc/systemd/system/ctrl-alt-del.target ? /dev/null.

Reload the daemon to take effect: 

$ sudo systemctl daemon-reload'
  impact 0.7
  tag check_id: 'C-74745r1068362_chk'
  tag severity: 'high'
  tag gid: 'V-270712'
  tag rid: 'SV-270712r1068363_rule'
  tag stig_id: 'UBTU-24-300026'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-74646r1067121_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe service('ctrl-alt-del.target') do
    it {should_not be_enabled}
    it {should_not be_running}
  end
end
