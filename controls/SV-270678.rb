control 'SV-270678' do
  title 'Ubuntu 24.04 LTS must initiate a graphical session lock after 10 minutes of inactivity.'
  desc 'A session lock is a temporary action taken when a user stops work and moves away from the immediate physical vicinity of the information system but does not want to log out because of the temporary nature of the absence. 
 
The session lock is implemented at the point where session activity can be determined. 
 
Regardless of where the session lock is determined and implemented, once invoked, a session lock of Ubuntu 24.04 LTS must remain in place until the user reauthenticates. No other activity aside from reauthentication must unlock the system.'
  desc 'check', 'Note: If Ubuntu 24.04 LTS does not have a graphical user interface installed, this requirement is not applicable. 

Verify the Ubuntu operation system has a graphical user interface session lock configured to activate after 10 minutes of inactivity with the following commands:  
 
Set the following settings to verify the graphical user interface session is configured to lock the graphical user session after 10 minutes of inactivity: 
  
**$ gsettings get org.gnome.desktop.screensaver lock-enabled
true

$ gsettings get org.gnome.desktop.screensaver lock-delay
uint32 0

$ gsettings get org.gnome.desktop.session idle-delay
uint32 600

Note: If "lock-enabled" is not set to "true", this is a finding.

If "lock-delay" is set to a value greater than "0", or if "idle-delay" is set to a value greater than "600", or either settings are missing, this is a finding.'
  desc 'fix', 'Configure Ubuntu 24.04 LTS to lock the current graphical user interface session after 10 minutes of inactivity.  
 
Create or edit a file named /etc/dconf/db/local.d/00-screensaver with the following contents:

[org/gnome/desktop/session]
idle-delay=uint32 900

[org/gnome/desktop/screensaver]
lock-enabled=true
lock-delay=uint32 600

Update the dconf settings:

$ sudo dconf update'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000029-GPOS-00010'
  tag satisfies: ['SRG-OS-000029-GPOS-00010', 'SRG-OS-000031-GPOS-00012']
  tag gid: 'V-270678'
  tag rid: 'SV-270678r1101791_rule'
  tag stig_id: 'UBTU-24-200020'
  tag fix_id: 'F-74612r1101790_fix'
  tag cci: ['CCI-000057', 'CCI-000060']
  tag nist: ['AC-11 a', 'AC-11 (1)']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }

  if package('gnome-desktop3').installed?
    describe command("gsettings get org.gnome.desktop.session idle-delay | cut -d ' ' -f2") do
      its('stdout.strip') { should cmp <= input('system_inactivity_timeout') }
    end
  else
    impact 0.0
    describe 'The system does not have GNOME installed' do
      skip "The system does not have GNOME installed, this requirement is Not
        Applicable."
    end
  end
end
