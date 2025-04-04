control 'SV-270679' do
  title "Ubuntu 24.04 LTS must retain a user's session lock until the user reestablishes access using established identification and authentication procedures."
  desc 'A session lock is a temporary action taken when a user stops work and moves away from the immediate physical vicinity of the information system but does not want to log out because of the temporary nature of the absence. 
 
The session lock is implemented at the point where session activity can be determined. 
 
Regardless of where the session lock is determined and implemented, once invoked, a session lock of Ubuntu 24.04 LTS must remain in place until the user reauthenticates. No other activity aside from reauthentication must unlock the system.'
  desc 'check', 'Note: If Ubuntu 24.04 LTS does not have a graphical user interface installed, this requirement is not applicable. 
 
Verify the Ubuntu operation system has a graphical user interface session lock enabled with the following command:
 
$ sudo gsettings get org.gnome.desktop.screensaver lock-enabled
true  
 
If "lock-enabled" is not set to "true", this is a finding.'
  desc 'fix', 'Configure Ubuntu 24.04 LTS to allow a user to lock the current graphical user interface session.  
 
Set the "lock-enabled" setting to allow graphical user interface session locks with the following command:  
 
$ gsettings set org.gnome.desktop.screensaver lock-enabled true'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000028-GPOS-00009'
  tag satisfies: ['SRG-OS-000028-GPOS-00009', 'SRG-OS-000030-GPOS-00011']
  tag gid: 'V-270679'
  tag rid: 'SV-270679r1066526_rule'
  tag stig_id: 'UBTU-24-200040'
  tag fix_id: 'F-74613r1066525_fix'
  tag cci: ['CCI-000056']
  tag nist: ['AC-11 b']
  tag 'host'

  output = command('which Xorg').exit_status

  if output == 0
    describe command('gsettings get org.gnome.desktop.screensaver lock-enabled').stdout.strip do
      it { should cmp true }
    end
  else
    describe command('which Xorg').exit_status do
      skip("GUI not installed.\nwhich Xorg exit_status: " + command('which Xorg').exit_status.to_s)
    end
  end
end
