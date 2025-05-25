## 1.4.1 (2025/05/24)

This is a bugfix release, that fixes the Bitmesssage Connections setting from working properly for some options. If upgrading, you may need to save the Bitmessage Connections configuration setting after the upgrade.

Additionally, the post menu has changed to include d Set Thread Attributes menu. This will render fine for new posts, but old posts that have already had their HTML rendered, will still have the old (non-functional) menu. In order for old posts to show the new menu, select the Diag link at the top of the page and click Regenerate All HTML. Each post will then regenerate its HTML the next time it's loaded. The speed of loading posts will only be slower for their first load, then improve on subsequent loadings.

 - Fix Allow Download post button starting attachment download
 - Fix separation of threads on board page
 - Fix thread size limitation of javascript thread post updater
 - Fix not showing debug information for thread OP
 - Fix Bitmessage Connection setting not being applied for some options
 - Fix post overflow when using ASCII or CODE formatting
 - Fix highlight text formatting
 - Fix i2psnark standalone URL
 - Add option to replace attachment filenames
 - Add ability of Pages to use Jinja2 (example pages will be available in a future update)
 - Add ability to schedule post at a random time in the future between two epochs
 - Add ability to locally force post max height for individual threads
 - Add user Option to force disable post max height
 - Add Config and user Option to set base font size 
 - Add setting to select default post dropdown for attachment upload method
 - Add code style text formatting
 - Add MiNode install instructions to INSTALL.md
 - Periodically restart qBittorrent to prevent connection issues
 - Style changes to be more mobile friendly
 - Refactor setting post attributes into one settings page
 - Update qBittorrent to 5.1.0
 - Update qbittorrent-api to 2025.5.0


## 1.4.0 (2025/04/26)

Upgrading from version 1.3.0 can be performed with the following steps:

1. Stop docker containers: cd Bitchan/docker && docker compose down
2. Delete i2pd.conf: sudo rm -rf /usr/local/bitchan-docker/i2pd/i2pd.conf
3. Delete torrc: sudo rm -rf /usr/local/bitchan-docker/tor/torrc 
4. Get latest code: cd Bitchan && git pull 
5. Build Bitchan: cd Bitchan/docker && make daemon

After building, you may need to change the Bitmessage Connections option on the Config page before connections can occur.

 - Fix display of image EXIF data
 - Fix showing file names for undownloaded I2P/BitTorrent post attachments
 - Fix deleting database entries for torrents
 - Fix exception when formatting certain post text
 - Fix sending GPG message without post body text
 - Fix issue updating posts on long threads
 - Fix error when deleting posts from Search page
 - Fix board wipe not deleting threads
 - Fix page to jump when loading by using fixed thumbnail dimensions
 - Fix bug reports not respecting post refractory period
 - Add ability to schedule automatic posting at a future time
 - Add ability to perform additional Proof of Work (POW) to post
 - Add ability to create Rules for Threads
 - Add Thread Rule: Sort Replies by POW (instead of sent time)
 - Add Thread Rule: Require Proof of Work (POW) to Reply
 - Add Board Rule: Require Proof of Work (POW) to Post
 - Add Board Rule: Require Post Attachment
 - Add config option to allow/disallow kiosk users from selecting POW to be performed for posts
 - Add config option to select boards to be Read Only
 - Add ability to create static HTML Pages
 - Add MiNode 0.3.5 for Bitmessage communication over I2P and set as default
 - Add MiNode options in Bitmessage Connections config dropdown
 - Add hash validation requirement for all pip libraries
 - Add ability to attach image to post by pasting from clipboard
 - Add thumbnails for attached images during post composition
 - Add enlarged image popup on thumbnail hover during post composition
 - Add option to automatically start seeding I2P BitTorrent attachments for your own posts
 - Add option to disable search for users when in Kiosk mode
 - Add ability to search for STEG posts
 - Add option to use purple/i2pd, geti2p/i2p, or i2pplus
 - Add ability to search for posts using from address
 - Add Board Rule: Disallow Post Attachments
 - Add Post Max Height (25em) to Options
 - Change default Bitmessage connection mode to I2P-Only
 - Enable tor DDoS protection
 - Exclude global admins from rate-limiting
 - Remove rate-limiting for global admins
 - Remove post numbers
 - Remove use of NTP
 - Use randomly-generated password for i2pd webconsole
 - Optimize MySQL server configuration using MySQLTune
 - Optimizations to reduce CPU usage
 - Optimize code to improve page load times
 - Significant decrease in daemon idle CPU use
 - Prevent regular users from setting default post From Address in Kiosk Mode
 - Change max banner image width from 650 to 1200 px
 - Update Python from 3.9 to 3.11
 - Update i2pd to 2.56.0
 - Update tor to 0.4.9.2-alpha
 - Update QBittorrent to 5.1.0rc1
 - Update libtorrent to 2.0.11
 - Update Flask-Session to 0.8.0 and switch from deprecated filesystem to cachelib
 - Increase session threshold to 50,000


## 1.3.0 (2024/04/20)

This release has several incompatibilities with v1.2.0, therefore v1.2.0 and v1.3.0 will not be able to communicate with each other. Due to significant changes, there isn't an option to upgrade from v1.2.0 to v1.3.0, so a clean install will need to be performed.

Notes on BitTorrent over I2P feature: The introduction of BitTorrent over I2P as a post attachment method removes the reliance on 3rd party upload sites for hosting attachment data and improves the privacy and security of the transmitted data. Only torrents with I2P trackers will function. Trackers with a TLD other than i2p are prohibited and will result in an error if you try to set non-I2P trackers on the configuration page or attempt to send or receive an attachment using BitTorrent over I2P using a non-I2P tracker.

 - Fix b64 encoding label when adding address book entry to bitmessage
 - Fix error when replying to or forwarding mailbox messages
 - Fix decoding error in steg message
 - Fix index error when attaching files to post
 - Fix requiring manual CSS override if received Admin Command with CSS is the same as what's currently set
 - Fix deleting boards/lists from private lists
 - Fix OP healing bug that prevents replies from being sent if OP is too large
 - Fix ability to use Bitmessage upload method when it's disabled
 - Fix post preview when captchas are disabled
 - Add I2P BitTorrent as an attachment upload method using qBittorrent
 - Add RSS feed support for Boards and Threads
 - Add tor Hidden Service PoW support for DoS protection
 - Add global sliding window request rate limiter (implemented for RSS requests)
 - Add Kiosk User Management System
 - Add Board Rule: Restrict Thread Creation to Owners, Admins, and Thread Creation Users
 - Add option to disable downloading attachments from upload sites or i2p torrents
 - Add option to select what happens when a post/thread is remotely deleted (options: hide or delete)
 - Add ability to restrict board/list. Similar to unlisted, but attempting to load the board will result in 404 Error as though it doesn't exist
 - Add option to hide BitChan version
 - Add option to set web page title text
 - Add ellipses to page navigation when there are an excessive number of pages
 - Add display of EXIF data for image attachments
 - Add number of replies for each post on /search and /recent
 - Add /random_post endpoint to take you to a random post
 - Add ability to hide passphrases for individual boards/lists rather than global setting
 - Add ability to search a specific board
 - Add ability to download torrent file if I2P/BitTorrent post attachment is unencrypted
 - Add AVIF and APNG image support
 - Remove stale message expire time entries
 - Remove Python3 virtualenv from Docker volume
 - Switch from using Sqlite3 to MySQL
 - Update Python packages
 - Update tor to 0.4.8.10
 - Update i2pd to 2.51.0


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
 - Add Success to access graph on Stats page
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
