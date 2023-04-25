## 1.2.0 (2023/04/24)

This release incorporates several changes that are incompatible with the previous version. Therefore, it is recommended to do a clean install.

This release also enables BitChan to be installed natively in a Debian-based Linux operating system without the use of Docker. This is now the recommended installation method. See INSTALL.md for instructions.

 - Fix hiding posts if thread is hidden
 - Fix preventing posting on hidden threads
 - Fix Automatic Wipe of boards
 - Fix cross-post links
 - Fix starting attachment downloads from /recent page
 - Fix adding boards/lists from passphrase links in posts
 - Fix issue if height/width not able to be determined from attachment images/video
 - Fix display of video attachments with greater height than width
 - Fix deleting and regenerating posts
 - Fix upload site check that may prevent downloading some attachments
 - Fix issue with post HTML cache not updating after an attachment download completes
 - Fix saving post formatting/HTML
 - Fix premature end of post replacement matching
 - Fix table checkerboard coloring on recent page applying to post dropdowns
 - Add ability to reply to threads without refreshing the page
 - Add ability to heal missing OP of OP-less threads
 - Add additional PGP functionality for posts
 - Add ability to combine Bitmessage knownnodes.dat (/diag page)
 - Add ability to switch between ordering posts using sent and received timestamps
 - Add ability to ban attachments and automatically delete posts with banned attachments
 - Add ability to ban strings/regexes from post body/subject and automatically delete posts
 - Add ability to set automatic string replacements
 - Add ability to set post header time timezone and 12/24-hour format
 - Add Maintenance Mode
 - Add highlighting to refreshed posts in threads
 - Add custom List banners on home page
 - Add BitChan Environment Info to /status page
 - Add warning when attempting to add unlisted Boards/Lists to a List
 - Add Bitmessage Inbound and Outbound Connections to /status page
 - Add ability to disable use of "No Encryption" attachment encryption option
 - Add ability to set the maximum post size
 - Add kiosk TTL options to set max TTL or force TTL
 - Add ability to see post preview with text formatting before posting
 - Add Attachment Option: Change Spoiler
 - Add blurred spoilers
 - Add ability to spoiler video attachments
 - Add ability to disable upload sites
 - Add ability to set bitmessage in/out connection settings with simple dropdown
 - Add post attachment upload progress page
 - Remove Admin Command: Custom Spoiler
 - Improve data display on /stats page
 - Update tor to 0.4.7.9
 - Update i2pd to 2.47.0


## 1.1.1 (2022/05/15)

Users with BitChan < 0.11.0 can not upgrade and will need to follow the instructions listed in the README to clean and install BitChan. Users with Bitchan >= 0.11.0 that wish to upgrade need to pull the new code, delete a volume, then build, as follows:

```
cd BitChan/docker
sudo docker-compose down
torsocks git pull
docker volume rm docker_nginx docker_tor docker_tor_etc docker_i2p docker_i2psnark
sudo torsocks docker-compose pull
sudo torsocks docker-compose up --build -d --remove-orphans
```

 - Fix IP binding of I2P
 - Fix building on ARM
 - Fix populating reply box with highlighted text and post ID
 - Fix applying proper formatting tags to post test when composing
 - Fix generating reply links when posts are received out of order
 - Compile tor instead of using pre-compiled binaries
 - Switch from using i2p to i2pd
 - Add ability to expand all images of a thread

## 1.1.0 (2022/05/02)

Users with BitChan < 0.11.0 can not upgrade and will need to follow the instructions listed in the README to clean and install BitChan. Users with Bitchan >= 0.11.0 that wish to upgrade need to pull the new code, delete a volume, then build, as follows:

```
cd BitChan/docker
sudo docker-compose down
torsocks git pull
docker volume rm docker_nginx docker_tor docker_tor_etc
sudo torsocks docker-compose pull
sudo torsocks docker-compose up --build -d --remove-orphans
```

 - Fix remote file exploit bug
 - Fix locks not being respected by the frontend
 - Fix update of board/thread timestamp when post/thread is deleted
 - Fix adding to mod log when deleting post/thread from recent/search pages
 - Fix being able to post to nonexistent thread
 - Fix database lock issues when processing many posts
 - Fix deleting post with password
 - Add I2P support (for uploads, downloads, and hidden service)
 - Add I2P upload sites (bunkerfiles.i2p, 0xff.i2p)
 - Add reply popup
 - Add Ajax loading of new posts on thread pages
 - Add ability to unlist board or list (hiding its existence from public view when in kiosk mode)
 - Add "Last x Posts" thread view
 - Add option for automatic session-banning if verification requests exceed rate-limit
 - Add Boards and List pages
 - Add Time To Post (TTP) countdown if kiosk and post refractory period enabled
 - Add Game Bot (first games: chess and tic-tac-toe)
 - Add ability for users (in kiosk mode) to set CSS/JS/Theme and other options, and export/import options
 - Add ability to locally-restore remotely-deleted posts/threads
 - Add tor hidden onion for incoming Bitmessage connections and enable Bitmessage incoming connections over tor v3 hidden onion
 - Add ability to regenerate onion address for incoming Bitmessage connections
 - Add ability to set a password when posting that can be used to delete the post later
 - Add kiosk permissions: Janitor (can locally delete posts/threads from kiosk)
 - Add redirection to the proper page after verifying, rather than the home page (Referrer-Policy set to same-origin)
 - Add ability to filter mod log
 - Switch from using XML-RPC to JSON-RPC
 - Set post images to lazyload
 - Discard posts received for deleted threads
 - Move storage of post captcha from session to database
 - Update tor to 0.4.6.7 (blocks connections to v2 onion addresses)


## 1.0.0 (2021/10/31)

Users with BitChan < 0.11.0 can not upgrade and will need to follow the instructions listed in the README to clean and install BitChan. Users with Bitchan >= 0.11.0 can merely pull the new code, delete several volumes, and rebuild to upgrade to 1.0.0:

```
cd BitChan/docker
sudo docker-compose down
git pull
docker volume rm docker_nginx
docker volume rm docker_tor_etc
sudo docker-compose up --build -d
```

 - fix install issues
 - fix leaving boards/lists
 - fix session size issue
 - fix sqlalchemy breaking flask-sqlalchemy
 - fix displaying upload progress on status page
 - fix improper substring regex matches
 - fix board/list sorting (now case-insensitive)
 - fix automatic deletion of messages from sent folder of Bitmessage
 - fix Max Auto-Download size calculation
 - fix decryption size exploit
 - add popup images and post summary on reply link hover
 - add ability to bulk join from list
 - add Kiosk Mode
 - add Kiosk Mode features: login, permissions, post rate limit
 - refactor to allow multithreaded frontend (for Kiosk mode)
 - add address to message when deleting post with comment
 - add check if Bitmessage is restarting before sending messages
 - add the ability to enable hidden v3 onion service (random or custom address)
 - remove PNG from steg insertion (LSB mode) due to excessive RAM use on large images
 - add error-handling for failed uploads
 - page loading optimizations
 - add post option: sage
 - add bulk adding to lists
 - add option to prevent automatically downloading from unknown upload sites
 - add post stats to index cards
 - add incrementing post numbering per board
 - add embedded audio play support for OPUS and M4A
 - add post option: Delete Post with Comment (For You)
 - add captcha for posting
 - add DoS protection
 - add overboard page
 - add catalog page
 - add search page
 - add recent posts page (all posts and individual board posts)
 - add reference link limit (max 50)
 - add ability to hide passphrases from Board/List Information
 - add ability to pin/lock threads


## 0.11.1 (2021/03/07)

This is a bugfix release. Users with BitChan < 0.11.0 will need to follow the instructions listed in the 0.11.0 changelog notes, below, to upgrade to this version. Users with Bitchan 0.11.0 can merely pull the new code and rebuild to upgrade to 0.11.1:

```bash
cd BitChan/docker
sudo docker-compose down
git pull
sudo docker-compose up --build -d
```

 - fix creating posts with attachments greater than 5 MB


## 0.11.0 (2021/03/06)

This beta release fixes bugs and implements new features. Due to numerous database incompatibilities with v0.10.0 and lower, you will need to delete all bitchan and bitmessage user data (volumes) to upgrade to this version. It is recommended to export your information before upgrading, which will provide you with the passphrases used to join boards, lists, and recreate your identities, and the addresses to repopulate your address book. Once BitChan becomes more stable and leaves beta, alembic will be used to update the database when upgrading, which will permit migrating to a new version without having to delete user data.

If running a version prior to 0.11.0, use these commands to delete all user data and build 0.11.0:

```bash
cd BitChan/docker
sudo docker-compose down
sudo docker volume rm docker_bitmessage
sudo docker volume rm docker_bitchan
git pull
sudo docker-compose up --build -d
```

 - fix message TTL always being 4 days
 - fix issues preventing the joining/creation of boards/lists
 - fix missing functionality when JavaScript is disabled
 - fix inability to add/remove list items
 - fix infinite loop if error occurs during attachment download
 - fix enlarging videos on click
 - fix inability to join with passphrase link if "/" is in the passphrase
 - fix From Address list generation issue
 - fix issues if an attachment has multiple periods in the file name
 - fix potential inconsistencies in board/list passphrases
 - fix missing subject in OP placeholder
 - add ability to attach multiple files
 - add ability to specify file attachment order
 - add ability to specify which image to insert steg
 - add more attachment upload sites
 - add ability to add and edit attachment upload sites
 - add ability to save new attachment upload site settings from posts
 - add share URLs that allow easy joining of boards/lists, with optional embedding of PGP passphrases
 - add Rule to allow PGP passphrases of boards/lists to be saved in lists
 - add check that resync is complete before sending or processing certain messages
 - add check to prevent resync if a message POW is in progress
 - add lists to latest update display on home page
 - add timestamp to updated lists/boards on home page
 - add ability to configure max number of board/list updates to display on the home page
 - add TTL to mail message header info
 - add ability to set TTL of post
 - add ability for Owner to set a long description and spoiler image
 - add requirement that users must allow any custom CSS
 - add option to not encrypt post attachment
 - add #countdown(\[epoch\]) to display a countdown to an epoch timestamp
 - add #rps (rock, paper, scissors)
 - add Max Download Size setting to determine when to auto-download attachments (0 disables auto-download)
 - add option to resync when joining/creating boards/lists and creating Identities
 - add display of attachment source in post header
 - add use of encryption for attachments sent through Bitmessage
 - add BitChan log viewing page to easily view the log
 - add settings to control network connections (check file size, NTP, get random book quote)
 - add \[kern\], \[back\], \[caps\], \[center\], \[aa-s\], and \[aa-xs\] text formatting tags
 - add check if \[identity\] address is your own identity
 - remove forumfiles and uplovd upload sites (no longer working)

## 0.10.0 (2020/12/05)

This beta release fixes bugs and implements new features. Due to numerous database incompatibilities with v0.9.0, you will need to delete all bitchan and bitmessage user data (volumes) to upgrade to this version. It is recommended to back up any information before upgrading, which will provide you with the passphrases used to join boards, lists, and recreate your identities, and the addresses to repopulate your address book. Once BitChan becomes more stable and leaves beta, alembic will be used to update the database schema when upgrading, which will permit migrating to a new version without having to delete user data.

If upgrading from a prior version, use these commands to delete all user data and upgrade:

```bash
cd BitChan/docker
sudo docker-compose down
sudo docker volume rm docker_bitmessage
sudo docker volume rm docker_bitchan
git pull
sudo docker-compose up --build -d
```

 - fix install issue due to stegano dependency problem
 - fix inability to upload large files (timeout and RAM utilization issues)
 - fix inability to delete items from a list
 - fix list items not being removed from add dropdown after being added to list
 - fix bug preventing simultaneous download of message files with the same extension
 - fix inability to send bug reports
 - fix incorrect determination of command message expiration
 - fix in-browser audio player not appearing for OP with supported audio file attached
 - fix download resume not working
 - fix more than one #godsong on the same line
 - fix themes
 - replace PGP cipher CAST5 with AES256
 - replace hashing algorithm MD5 with SHA256
 - add header Referrer-Policy no-referrer
 - add mailboxes for identity addresses (read/compose)
 - add ability to compose message to address from post dropdown menu
 - add ability to set and change message PGP passphrase for boards/lists
 - add ability to set and change steganography PGP passphrase for boards
 - add ability to select file upload encryption cipher (XChaCha20-Poly1305, AES-GCM) and key length
 - add ability to select From Address when adding to lists
 - add ability to set default From Address for boards, threads, and lists
 - add ability to use custom flag images
 - add \[identity\] tag to insert Add to Address Book and Send Message links in post
 - add both boards and lists to top of board/list pages
 - add escaping of text that should be escaped
 - add linking of board/list passphrases in posts for one-click joining
 - add linking to Steg thread (if detected) from original posts on board view
 - add text highlighting, superscript, and subscript formatting
 - add board label as a link back to board when on a thread
 - add icon/link to scroll to the bottom of board/thread pages
 - add several additional post attachment upload sites
 - add ability to add/modify/delete attachment upload sites
 - add ability to add new attachment upload site from post
 - add sharable link that brings you to a page to join a board or list
 - replace sharable join link in post with board/list informational link 
 - limit display of filenames in posts to 100 characters
 - remove youtube embed tag
 - improve board/list From Address sorting and information display
 - improve crosslink with board/list name, description, and post subject
 - change web server to port 8000 (http://172.28.1.1:8000)
 - changes to user interface and styles

## 0.9.0 (2020/11/15)

Initial beta release
