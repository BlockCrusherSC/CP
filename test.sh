#!/bin/bash
# Set screensaver lock delay (seconds)
dconf write /org/cinnamon/desktop/screensaver/lock-delay 300

# Enable screensaver lock
dconf write /org/cinnamon/desktop/screensaver/lock-enabled true

# Enable screen lock when the session is idle
dconf write /org/cinnamon/settings-daemon/plugins/power/sleep-display-ac 10

# Set session idle delay (seconds)
dconf write /org/cinnamon/desktop/session/idle-delay 600

# Require password after suspend
dconf write /org/cinnamon/settings-daemon/plugins/power/sleep-inactive-ac-type 'suspend'
dconf write /org/cinnamon/settings-daemon/plugins/power/sleep-inactive-battery-type 'suspend'

# Lock the screen on suspend
dconf write /org/cinnamon/settings-daemon/plugins/power/lock-on-suspend true

# Disable file indexing for privacy
dconf write /org/cinnamon/desktop/search-providers/enabled "[]"

# Clear recent files
dconf write /org/cinnamon/desktop/privacy/recent-files-max-age 0

# Disable saving recent files
dconf write /org/cinnamon/desktop/privacy/recent-files-enabled false

# Disable automatic connections to new networks
nmcli networking off

# Disable Wi-Fi if not needed
nmcli radio wifi off
