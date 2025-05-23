<h1 align="center">BitChan Manual</h1>

- [About](#about){.link}
- [Boards and Lists](#boards-and-lists){.link}
- [Frequently Asked Questions](#frequently-asked-questions){.link}
- [Permissions](#permissions){.link}
- [Posts](#posts){.link}
  - [Composing Posts](#composing-posts){.link}
  - [Text Modifications](#text-modifications){.link}
    - [Formatting](#formatting){.link}
    - [Functions](#functions){.link}
  - [Supported File Types](#supported-file-types){.link}
  - [Steganography](#steganography){.link}
- [Post Header](#post-header){.link}
  - [Author Arrow Dropdown Menu](#author-arrow-dropdown-menu){.link}
  - [Post Arrow Dropdown Menu](#post-arrow-dropdown-menu){.link}
- [Threads](#threads){.link}
- [Thread Cards](#thread-cards){.link}
  - [Homepage Board Preview](#homepage-board-preview){.link}
  - [Overboard](#overboard){.link}
  - [Catalogs](#catalogs){.link}
- [Recent](#recent){.link}
- [Board and List Creation](#board-and-list-creation){.link}
  - [Creating Public Boards and Lists](#creating-public-boards-and-lists){.link}
  - [Creating Private Boards and Lists](#creating-private-boards-and-lists){.link}
  - [Board and List Information](#board-and-list-information){.link}
  - [Owner Options](#owner-options){.link}
- [Rules](#rules){.link}
- [Identities](#identities){.link}
  - [Mailboxes](#mailboxes){.link}
- [Address Book](#address-book){.link}
- [Configuration](#configuration){.link}
  - [General Settings](#general-settings){.link}
  - [Bitmessage Settings](#bitmessage-settings){.link}
  - [Kiosk Settings](#kiosk-settings){.link}
  - [Security Settings](#security-settings){.link}
  - [RSS Settings](#rss-settings){.link}
  - [Export](#export){.link}
  - [Post Attachment Upload Sites](#post-attachment-upload-sites){.link}
  - [Custom Flags](#custom-flags){.link}
  - [Hidden Tor Onion Service](#hidden-onion-service){.link}
  - [Hidden I2P Service](#hidden-i2p-service){.link}
  - [Board and List Options](#board-and-list-options){.link}
- [Kiosk Mode](#kiosk-mode){.link}
- [Status](#status){.link}
- [Stats](#stats){.link}
- [Mod Log](#mod-log){.link}
- [BC Log](#bc-log){.link}
- [Options Menu](#options-menu){.link}
  - [CSS Tab](#css-tab){.link}
  - [JS Tab](#js-tab){.link}
  - [Options Tab](#options-tab){.link}
- [Bug](#bug){.link}
- [Donate](#donate){.link}
- [Developer Information](#developer-information){.link}

# About

BitChan is a decentralized anonymous imageboard inspired by [Bitboard](https://github.com/michrob/bitboard){.link} and built on top of [Bitmessage](https://bitmessage.org){.link} with [Tor](https://www.torproject.org){.link}, [I2P](https://i2pd.website){.link}, and [GnuPG](https://gnupg.org){.link}.

BitChan solves a number of security and free speech problems that have plagued most imageboards. Centralized imageboards can be taken offline or hijacked and can leak user data. BitChan reduces the likelihood of this by being decentralized, requiring all connections to go through Tor and I2P, and not requiring Javascript.

When installed locally on your computer, BitChan acts as an extension to Bitmessage, a decentralized, blockchain-based messaging program. Bitmessage relies on public key encryption similar to PGP and decentralized message delivery, which due to the fact that every message is distributed to every client, also provides plausible deniability (i.e. no one knows who the message was intended to go to). Bitmessage handles the sending and receiving of messages and BitChan acts as a sophisticated message processor, which includes a web front end. All communication happens over the Tor onion routing network or I2P for anonymity and every BitChan message is encrypted using GPG, an open source version of PGP (Pretty Good Privacy). Instead of connecting to a stranger's server and volunteering potentially identifying information, BitChan anonymously adds your message to the Bitmessage block. Everyone on the Bitmessage network downloads and shares your encrypted messages and only those with the correct credentials can decrypt them.

Users of centralized forums often have to deal with overzealous moderators and sometimes even pressure from State powers that tend to suffocate the forum's culture. BitChan's moderation is multifaceted, but to be brief, the option exists to create entirely unmoderatable boards. Due to its decentralized design, BitChan cannot be moderated by its developers or the government. Indeed, there is no way to disconnect BitChan from the internet, and as long as people are still running Bitmessage, BitChan lives completely untouchable by any authority. With that said, boards can be created with a variety of rules which allow board owners or admins to moderate them if so desired. Unmoderated boards can be locally moderated by the user. Additionally, users can set their install to act as a Kiosk and enable a Tor Hidden Onion service or Hidden I2P Service to allow anonymous users to utilize their install through an .onion address, however when accessing BitChan in this way, you will be constrained by the settings that user sets for their BitChan install. In order to utilize the full features of BitChan, including reliability and a censor-free environment, you will need to install it locally on your computer.

BitChan features boards for forum-like discussions with image and file sharing, lists to organize and share other boards and lists, and a host of additional features. Board/list management is possible via the application of owner, admin, and user permissions. Boards and lists can be public or private and with or without owners or admins, allowing a full range of options from completely unmoderatable to strict, where only select addresses are allowed to post or modify list contents.

# Boards and Lists

Both boards and lists are built on what Bitmessage calls chans (short for channels), each with an address that allows a public key to be derived from which messages can be encrypted. Within BitChan, messages sent to a board/list are further encrypted again so only members of that board with the proper credentials can decrypt and read them. To become a member of a board (or list), you must know the passphrase used to generate the Bitmessage address and the PGP passphrase(s) used to decrypt BitChan messages. Under normal circumstances, anyone that has the passphrase that generates the address of the board/list and the message PGP passphrase(s) can read the messages sent to it. Under the most relaxed board configuration, you can use any address to send messages to a board, including the same board's address that's receiving it (considered anonymous), your own identity addresses (personal address only you can send from), or other board/list addresses (addresses all members of those boards/lists can send from). More about board creation, configuration and permissions can be found in [Board and List Creation](#board-and-list-creation){.link}.

Although the functionality of boards and lists are very different, they both operate on Bitmessage chans. The messages received in chans are processed to determine if they originated from BitChan by their decryptability and their content. BitChan parses the contents of messages and presents the data in a meaningful way that extends the functionality of mere text communication.

Boards act as communication platforms for producing threads consisting of posts, with added functionality, including text formatting (color, style), multiple file attachments (with any extension and in-browser embedding of image, audio, and video), and admin moderation, among others. Public boards allow anyone to post, including from the address of the board itself (an anonymous post) or from a different address (similar to using tripcodes). Private boards allow only specific addresses to post. If a public board does not have an owner or admin set, it is completely unmoderatable and posts cannot be removed (unless an [automatic wipe rule](#automatic-wipe){.link} was set when it was created).

Lists act as a medium to compile a list of other boards and lists that can be modified and shared with others. Users can join any of the boards or lists on the list. Any user can add to a public list, but only authorized users may add to a private list. Owners and admins may delete items from both public and private lists. If a public list does not have an owner or admin set, it is completely unmoderatable and can only grow in size (unless an [automatic wipe rule](#automatic-wipe){.link} was set when it was created). Ticking the first checkbox when viewing a list will select all un-joined entries. Clicking **Join All Checked** at the bottom of the list will automatically join the selected entries. Note: Bulk joining skips the prompt to enter custom PGP passphrases, however, those entries which include their own passphrases will automatically be joined with those passphrases.

Information about a board or list can be found in the "Information" dropdown box near the top of their page. See [Board and List Information](#board-and-list-information){.link} for what is included.

# Frequently Asked Questions

## How does this differ from a traditional imageboard?

 - Unidentifiable: BitChan utilizes Bitmessage for communication, which sends every encrypted message to everyone else, providing anonymity and plausible deniability as to the origin of a message.
 - Uncensorable: If you are permitted to post on a board and there is no owner or admin for that board, it is impossible for your message to be censored. If a board has an owner or admin, your message can be deleted by the owner or admin.

## Can I create my own board?

Yes, see [Board and List Creation](#board-and-list-creation){.link}.

## Why does my post not appear immediately after clicking post?

There could be a few reasons for this. The most common is that the Bitmessage network, which BitChan utilizes to send and receive posts, requires time to proliferate any message. A message is not displayed until Bitmessage receives it and BitChan processes it. Another reason is that larger messages take longer to produce proof of work (POW) which Bitmessage requires to authenticate messages. A third reason is that, if you include a large file and choose to upload it to an external file host, the upload must be successful before BitChan will attempt to send the post. Sometimes external file hosts can malfunction and posting will fail if this happens.

## Why are there no threads/posts that appear immediately after joining a board?

You will not see any activity on a recently joined board, assuming it has had recent activity, unless 'resync' was selected when joining it. Resync forces Bitmessage to scan its block for old messages and BitChan will display them if any are found. If this option is not used only posts received after joining will be seen. NOTE: resync can only display activity which have unexpired time to live (TTL). Expired activity is automatically purged from the Bitmessage network and so cannot be recovered.

## Will my posts and attachments live forever?

BitChan utilizes Bitmessage to communicate via messages. Each of these messages has a user-set time to live (TTL), which is the duration it will be propagated on the Bitmessage network. If a user makes a post on a board at time X with a TTL of 28 days (the maximum allowed), any other user running BitChan and who is also member of that board will receive that post between time X and X + 28 days. If the user doesn't have BitChan running since before X (or has it running but hasn't joined the board), and doesn't start BitChan until after X + 28 days (or has it running but doesn't join the board until after this period), the user will not receive the post.

## As the Owner of a board, what will happen to my board if I don't keep BitChan running?

Users that have joined your board can continue posting to your board regardless if the owner keeps BitChan running or not. However, if you have set any additional Owner Options after the board creation, you will need to run BitChan at least every 28 days (preferably 20) in order to maintain those options. These include bans, the long description, permission changes, custom CSS, etc. 

## What's the deal with the "PGP passphrase" options for boards and lists?

The PGP passphrase is populated by default unless a custom one is provided. As an additional level of privacy, every post is PGP encrypted with a PGP passphrase. If users don't want to use the default passphrase they can change it. Only users who have the same PGP passphrase will see content encrypted with it. NOTE: only change this passphrase if you are sure others are aware of its use, otherwise you will no longer see any content that is encrypted with the default or any other passphrase.

## Why do I have to click "Allow Download" for every post with an attachment?

By default, BitChan will not auto-download attachments from upload sites. If you would like to automatically download attachments if they are below a certain size, change **Attachment Auto-Download Max Size** on the configuration page.

## How do I securely get people to join my board?

If your board is public, just share the board passphrase or share link. If your board is private, you will have to add the Identity address of each person to the User addresses field under 'Owner Options' on the index page of your board. 

# Permissions

For both boards and lists, there can be Owner, Admin, and User addresses specified. If you control an address that is an Owner or Admin of a board or list, you can perform special actions that affect all members. Normally, when you click a link for a thread or post to be deleted from a board, this occurs only locally on your computer. However, Owners and Admins have the ability to delete threads and posts for all users of the board. For private lists, Owners and Admins can delete list items and the changes will be reflected for all users of the list.

Owners of private boards and lists will see an [Owner Options](#owner-options){.link} menu at the top of the page, where they can modify the parameters of the board or list. Additionally, when an Owner or Admin selects the dropdown menu next to a user's address or post ID, there will be additional options available to them. See the table, below, for what actions are available to each access level. Additionally, some actions may be restricted based on other settings of the board or list.

Ability | Board Owner | Board Admin | Janitor | User
--- |---|---|---|---
Modify Access Addresses | X |   |   | |
Set Custom Banner Image | X |   |   | |
Set Custom CSS | X |   |   | |
Set Word Replacements | X |   |   | |
Global Post/Thread Delete | X | X |   | |
Local Kiosk Post/Thread Delete |   |   | X | |
Ban Address | X | X |   | |
Delete from List | X | X |   | |
Post | X | X | X | X |
Add to List | X | X | X | X |

***Note: Be careful when banning an address, as there's no restriction to prevent you from banning your own address, and there is currently no ability to remove a ban. Consider adding addresses to the Restricted Address list instead, as this can be changed at a future point in time.***

# Posts

Posts are text-based messages on a board that can contain file attachments. If a file attachment is a supported image or video, the media will be displayed with the message. User-entered HTML is not allowed, but text can be stylized with various formatting tags. There are also several tags that provide the ability to execute functions (for example, dice rolls and coin flips, that because of the use of a seed, are random but will also appear the same to all users). More about these functions can be found in [Text Modifications](#text-modifications){.link}.

## Composing Posts

There are a number of options available when composing a post, which include:

***From Address***

This list includes all available addresses which are controlled by you and are allowed to post on the board. If the owner of the board has restricted certain addresses from posting and it's one you control, it will not appear in this list.

***Board/Thread Default From***

The address that's selected when this option is enabled will be pre-populated every time you compose a post. When viewing the index of a board, a Board Default From option is available and when viewing a thread, a Thread Default From option is available.

***Flag***

This list contains nation flags to choose from. The selected flag will appear next to the From Address in the post header. You can also utilize custom flags by adding them on the [Configuration](#configuration){.link} page.

***Subject***

If your post is an original post (OP) you can provide a subject. The subject line can be a maximum of 64 characters. No formatting is allowed here.

***Comment***

This is where the body of your post is written. HTML is forbidden but several [Text Modifications](#text-modifications){.link} can be used.

***Post Formatting***

This menu contains buttons to facilitate formatting text in the comment. To use it, highlight text in the comment and press one of the buttons. This will surround the selected text with the formatting tags. More about formatting can be found in [Formatting](#formatting){.link}.

***TTL (seconds)***

This field allows you to set the TTL (time to live) of your message, in seconds. TTL is how long the Bitmessage network will propagate your post. This means that users can only receive your post if they download the Bitmessage block before the TTL expires. A short TTL will likely result in fewer people seeing your post and conversely, a longer TTL will increase the likelihood. The maximum TTL is 2419200 seconds (28 days) and is set by default. The minimum is 3600 seconds (1 hour). Note: if you've already downloaded the post, it will stay on the board beyond the TTL expiration because it has been downloaded locally to your computer.

***Sage***

Prevent the creation of a post from causing the thread to jump to the top of the board page or index page summary. This may be used when the poster doesn't think their post is that important and/or doesn't want to attract attention to the thread.

***Images/Files***

Select up to 4 file attachments to upload with your post. You can attach any file type, but only certain types will display as embedded media (see [Supported File Types](#supported-file-types){.link}). Since Bitmessage only supports sending messages of up to ~300 KB, any attachments larger than this will need to use one of the alternate, external upload sites. All files have their filename/extensions obscured and their contents encrypted prior to upload. If the total size of the attachment(s) is greater than 5 MB, it will be uploaded in the background and the post will be sent following a successful upload. The upload progress will be displayed on the [Status](#status){.link} page.

Next to each of the 4 attachment fields is a checkbox for spoilering your image. Rather than automatically displaying the image on the post, a placeholder image will be displayed until the user clicks it to display the original. This option only works with image attachments. There is also an 'X' for removing a selected file attachment.

***Strip EXIF (JPG/PNG only)***

This option removes EXIF data from .jpg and .png files prior to posting to a board.

***Upload Method***

Select the desired file transfer method. There are three different upload methods supported: Bitmessage, I2P BitTorrent, and 3rd Party Upload Sites.

Bitmessage is the most secure method of attaching a file, but only message (subject + comment + attachments + metadata) sizes of ~300 KB or less are permitted due to the size limitation of Bitmessage messages. Additionally, there is a drawback for sending large file sizes due to the required proof of work for sending Bitmessage messages. Sending large Bitmessage messages significantly increases how long it takes to send. External upload sites are supported, and additional measures have been taken to ensure the privacy of your file when uploaded to these sites. First, the attachment or attachments are zipped and encrypted with a random file name and extension. Then, the beginning and ends of the file, along with several randomly-sized segments at randomly-chosen locations in the file are removed, then uploaded to the external site. The random file parts are then sent with the message that's transmitted over Bitmessage. Once a user receives the post, the file is downloaded, the parts are inserted back into the file, then it's decrypted and unzipped. Additionally, and like all Bitmessage communication, all uploads and downloads are routed through tor.

I2P BitTorrent attachments are seeded over the I2P-only BitTorrent client qBittorrent to other BitChan instances that receive the post. Those BitChan instances also begin seeding the attachment data after fully downloading it, contributing to the data distribution. After a user-configured period of time, seeding stops and the torrent is deleted. Because OP healing is possible, by default, attachments are seeded longer for OPs than replies. The same encryption and obfuscation method is used, as described in the Bitmessage section, above.

The last upload method is using a 3rd party upload site. There are many upload sites on tor hidden onions and i2p eepsites that share a common API. These can only be accessed via tor and i2p, increasing security, but these should be considered the least secure of the three. You should assume many or all of these 3rd party upload sites are honeypots, making them the least secure of the three upload methods. The same encryption and obfuscation method is used, as described in the Bitmessage section, above.

***Upload Encryption***

Select which cipher and key bit length you want to use to encrypt your file attachments.

***Image to Insert Steg***

This dropdown lets you select the image to insert the steganographic comment. This only works for JPG attachments.

***Steg Comment (JPG only)***

Enter any text you desire to hide in your image with steganography. Some images may not work due to limitations of the software or a characteristic of the particular image. You should receive an error if it's unable to be performed. This only works for JPG attachments.

***Password to Delete***

A password can be supplied with a post to be able to delete the post at a later time. This password will initially be hashed with SHA512 and the hash sent with the post. At a later time, a request can be made to delete the post, which will send the unhashed, plain text password to all BitChan instances. These BitChan instances will hash the plain text password and compare it to the stored password hash for the post. If the hashes match, the post will be deleted. Because plain text passwords are sent with the request to delete the post (and for all intents and purposes, should be considered compromised because it has become publicly visible to all users), there are a few points to consider when choosing a password to use:

 1. Do not use a password that you would like to remain private (e.g. a password also used for bank account credentials).
 2. Do not use the same password for multiple posts, because one a request to delete a post is made, that password is visible to users (as those users can use that password to delete your other posts).
 3. Do write down your posts and passwords because the password will not be automatically saved for later retrieval.

## Text Modifications

There are several strings that will format text or execute functions in messages. These range from changing to color of text to generating random values from dice rolls.

### Formatting

Text formatting tags can be inserted manually in a post comment or can be automatically added around the highlighted text in a comment box by selecting one of the formatting buttons in the Post Formatting dropdown below the comment box.

<!-- Replace with text formatting -->

### Functions

Text functions can be used to perform random or calculated actions, such as dice rolling (#2d20), coin flipping (#flip), card pulling (#c13), and more.

<!-- Replace with text functions -->

## Supported File Types

BitChan supports attaching *any file type* to a post, but only certain types are supported for native display in the web browser. File types that can't be displayed will receive a placeholder image. You can still open the file by clicking the title link or save it by clicking the "dl" link.

The file types below have native support in most modern web browsers:

**Audio**: M4A, OPUS, WAV, MP3, OGG

**Images**: APNG, AVIF, GIF, JPG, JPEG, PNG, SVG, WEBP

**Video**: MP4, WEBM, OGG

## Steganography

Steganography is used to insert text messages into images attached to posts. A passphrase is used to PGP-encrypt the message being inserted into the image. You can use the default passphrase or set your own when creating or joining a board, or after board creation in the Board Information dropdown. If not using the default passphrase, be aware that any posts that contain an image with a message encrypted using the default passphrase will not be able to be decrypted/read. That is, messages encrypted with a passphrase that's different from the one currently set to decrypt with will not be able to be read. Therefore, if using a non-default passphrase, others must also be using the same non-default passphrase if you want to communicate with them. If you're being invited to a board with a non-default Steg Passphrase, you will typically be provided a non-default Steg Passphrase when you are provided the Board Passphrase used to join the board. 

# Post Header

The post header is what appears at the top of every post. It contains useful information such as an identicon, label, the post's arrow drop down menu, date and time, post ID, post number, sage icon, pinned thread icon, locked thread icon and the author's arrow dropdown menu, all of which are described below.

## Identicon

Every ID used to post has a unique icon associated with it, aka an identicon. These are deterministically created and every user sees the same one.

## Label

A post's label will read 'Anonymous' when the author is using the board's ID. Otherwise, it will either be last 9 characters of the Bitmessage ID or, if the ID is in your Address Book or Identities list, it will be the label that you have entered.

## Post Arrow Dropdown Menu

Every post will have an arrow dropdown menu. The options contain therein are described below.

### ID

This is the whole ID used to send post. Clicking the clipboard icon will copy the address to your clipboard (JavaScript must be enabled for this to work).

### Send Message

Clicking this link will take you the mail composition page. The 'To' field will be auto-populated with the ID.

### Add to Address Book

Clicking this link will prompt you to associate a label to the ID and enter it into your address book.

### Ban from Board For Everyone

This option is available if you control an ID that has 'Board Owner' permissions. Clicking this link will ban the ID from the board and delete all posts on the board authored by that ID.

### Block from all Boards For You

Clicking this link will locally delete all posts authored with this ID and prevent all future posts originating from this ID from showing, no matter what board they may be posted to.

### Block from this Board For You

Clicking this link will locally delete from the current board all posts authored with this ID and prevent all future posts originating from this ID from showing.

## Date and Time

This is the date and time when the post was sent.

## Post ID

The post ID is the unique 9 character string generated when a post is received. It is deterministically created and every user sees the same one.

## Post Number

This number tracks your local post count per board. Each new post increments the post number by one. BitChan post numbers work differently than centralized IBs. Due to the nature of a decentralized network, different installs of BitChan can have different posts per board (e.g. the result of joining a board at different times, locally deleting different threads/posts, etc.), the post numbers may not be the same. Since it's insecure to allow any single BitChan instance to designate a number for a post (although Post IDs are the same across all BitChan installs because they are determined by Bitmessage), the numbers you see represent the post order of a board for a particular BitChan install and won't necessarily align with what is seen on another BitChan install. Additionally, if posts are deleted, or posts are received out of order, the post numbers will be recalculated and adjusted to reflect the current state of the board, so there will never be gaps in post numbers.

## Sage

If a post has been saged a small leaf will be placed in the post header.

## Pinned Thread

If a thread has been pinned the original post will contain a pushpin in the post header. If the thread has been locally pinned the pushpin will be green, if remotely pinned it will be red, and if both it will be half green and half red.

## Locked Thread

If a thread has been locked the original post will contain a lock icon in the post header. If the thread has been locally locked the lock will be green, if remotely locked it will be red, and if both it will be half green and half red.

## Author Arrow Dropdown Menu

If the post is made with an ID other than the board's ID there will be an arrow dropdown menu. The options contained therein are described below.

### This Post's Short Cross-link

To make cross-linking more convenient, you can copy the short version here. Clicking the clipboard icon will copy the address to your clipboard (JavaScript must be enabled for this to work). When posted, the short cross-link will not indicate the originating board. 

### This Post's Long Cross-link

To make cross-linking more convenient, you can copy the long version here. Clicking the clipboard icon will copy the address to your clipboard (JavaScript must be enabled for this to work). When posted, the long cross-link will indicate the originating board. 

### This Post's Link

Right click and copy this link to get this post's url.

### Sticky Thread

A stickied (or pinned) thread stays at the top of a board. If you control an ID with Board Owner permissions then, for any thread on that board, you will see the option to pin it for everyone. Otherwise, you can locally pin any thread. The option to locally pin a thread exists regardless of the permission level.

### Lock Thread

Locking a thread prevents posts from being added. If you control an ID with Board Owner permissions then, for any thread on that board, you will see the option to lock it for everyone. Otherwise, you can locally lock any thread. Board Owners can still post to locked threads while, for everyone else, the post composition area will be removed to prevent posting. The option to locally lock a thread exists regardless of the permission level.

### Anchor Thread

Anchoring a thread prevents a thread from being bumped. If you control an ID with Board Owner permissions then, for any thread on that board, you will see the option to anchor it for everyone. Otherwise, you can locally anchor any thread. The option to locally anchor a thread exists regardless of the permission level.

### Delete Thread

If you control an ID with Board Owner permissions then, for any thread on that board, you will see the option to delete that thread for everyone. Otherwise, you can locally delete any thread. The option to locally delete a thread exists regardless of the permission level.

### Delete Post

If you control an ID with Board Owner permissions then, for any post on that board, you will see the option to delete that post for everyone. Otherwise, you can locally delete any post. The option to locally delete a post exists regardless of the permission level.

### Delete Post with Comment

If you control an ID with Board Owner permissions then, for any post on that board, you will see the option to delete that post and add a comment that everyone will see. Otherwise, you can locally delete any post and add a comment of your choice. The option to locally delete any post and add a comment exists regardless of the permission level.

### Delete Post Using Password

If you previously created a post and provided a Password to Delete, you may use this option to delete the post for all users. You must provide the same password that was originally provided. This password will be sent as plain text, and once this message propagates on the network and is received, BitChan will hash the password and compare it to the password hash that was originally saved when the post was made. If the hashes match, the post will be deleted.

# Threads

Threads are collections of posts under a single subject that are displayed sequentially in the order in which they were sent. The creation of a thread is based on the hash of a post that identifies itself as an OP. Any post that identifies itself as an OP is placed into its own new thread. Any post that identifies itself as a reply and references the hash of a non-existent OP/thread is placed under an OP placeholder. This prevents OP hijacking and other issues that can arise from messages being received out of order or otherwise attempting to disrupt a thread by containing inauthentic metadata.

# Thread Cards

Thread cards summarize threads and provide information about them at a glance. This information includes the age of the last post, posts per month (PPM), the thread subject, the original post (or at least part of it), the last three posts (at least part of them if they exist), total posts in the thread, total attachments in the thread, attachment to post ratio (A:P), the date of the original post and a last 100 posts link if that many exist. Next to each post there is \[O\] which shows a popup of the post when the mouse hovers over it.

## Homepage Board Preview

The homepage shows a number of boards and their most recently active threads in the form of thread cards. The number of boards displayed can be controlled on the configuration page by altering the 'Max Home Page Updates' setting.

## Overboard

The overboard shows thread cards for all threads in chronological order (most recent first) regardless of the board from which they originate.

## Catalogs

Each board has a catalog which shows thread cards for all threads on the board in chronological order (most recent first).

# Recent

The recent page shows a list for all posts in chronological order (most recent first) regardless of the board or thread from which they originate. Each item in the list displays the post ID, sent time, age of the post, whether it is an original post or not, if it was saged or not, if you control the identity which sent the post or not, the board the post is on and the subject of the thread the post appears on.

# Search

From this page you can search all of BitChan. The results show a list of posts in chronological order (most recent first). Each item in the list displays the post ID, sent time, age of the post, whether it is an original post or not, if it was saged or not, if you control the identity which sent the post or not, the board the post is on and the subject of the thread the post appears on. Hovering over the post ID will cause a popup of the post to appear.

# Board and List Creation

BitChan allows anyone to create and moderate boards and lists. Your board/list can be made

- Whenever
- For any reason
- About anything

To create a board or list simply click the **Create or Join** link in the sticky menu at the top and select your desired option:

- Create Public Board
- Create Private Board
- Create Public List
- Create Private List

Click **Next.** From here you can set Owner, Administrator, and User permissions by adding addresses from discovered or added boards, lists, identities, or manually added address book entries. Just select their respective checkboxes. You can add additional addresses for each user type as comma separated values in the **Additional Addresses** field.

All boards and lists require at least a label and description to be created.

***Label***

The label is a common name for the board or list. It corresponds to the url path normally seen on other imageboards (e.g. /fit/ in https://imageboard.com/fit/). Slashes '/' are not necessary when entering your label. The maximum label length is 25 characters.

***Description***

The description is a few words which describes the general theme of the board. The maximum description length is 200 characters.

***Owner Addresses***

Owner addresses have special abilities to moderate the board or list. This includes, but is not limited to, the ability to ban users, globally delete posts/threads, set custom CSS, set word replacements, modify address access, and set a custom banner image.

***Admin Addresses***

Admin addresses have a limited set of abilities to moderate a board or list. This includes the ability to delete posts/threads.

***User Addresses***

User addresses are those addresses that can only post or add to a list. This access level is only useful when creating a private board or list and you wish to give only specific addresses the ability to post or add to a list. This can be useful because you have the most control and can remove the addresses of users that cause problems on your board or list.

***Restricted Addresses***

Only available for public boards and public lists, restricted addresses are prevented from posting or modifying lists. When used in conjunction with **Require Identity to Post**, you can selectively ban individuals from posting or modifying lists.

***Extra String***

Since passphrases are used to create boards and lists, it's crucial to use a unique passphrase to ensure the board or list you're creating is unique. Furthermore, since passphrases are generated based on the parameters of the board or list (label, description, addresses, etc.), it's possible for two users to generate the same passphrase, resulting in the same board or list. Therefore, in order to increase the likelihood of generating a unique passphrases, a user can add extra characters to the end of their passphrase.

## Creating Public Boards and Lists

Public boards are the closest to an unmoderated board you can get. Any address except those on the restricted address list can create threads and posts. Addresses can be restricted after board creation by the owner, but because of the freedom afforded by Bitmessage to create an arbitrary number of unique addresses, if your address is restricted, you can simply make another one.

Similarly, for public lists, you can create a list for which any address (except those on the restricted address list) can add a board or list to.

## Creating Private Boards and Lists

By default, private boards and lists prevent users from posting or adding to unless given access. This access is enabled through the Owner, Admin, and User address lists set at the time the board or list is created. Additionally, these access lists can be changed after the board or list is created.

## Board and List Information

Near the top of board index pages and lists there exists information dropdown. Here you can find the following:

### Address

Every board and list has a unique and permanent Bitmessage address. To the right of the address is a button to copy it to your clipboard. This is provided for easier cross-linking (see [Functions](#functions){.link}).

### Link Without PGP Passphrases

This is a board/list link which you can share. This link contains (in encoded form) the board/list passphrase and functions exactly like a normal web link. If the recipient of the link has BitChan running, clicking it will load a page to join the board/list. BitChan's default message, attachment and steg PGP passphrases are used when joining boards from this link (only the default message PGP passphrase is used in the case of list links).

### Link With PGP Passphrases Below

This is a board/list link which you can share. This link contains (in encoded form) the board/list passphrase as well as the board/list's message PGP passphrase. Links for boards also include their attachment and steg PGP passphrases. This is useful for when a board/list uses custom PGP passphrases. This link functions exactly like a normal web link and if the recipient of the link has BitChan running, clicking it will load a page to join the board/list.

### BitChan Board/List Passphrase

Every board and list has a unique and permanent passphrase that is used to generate the address of the board or list. This passphrase is required to join the board or list and decrypt the messages sent to the address. Any user with the passphrase can join the board or list and begin interacting with it, depending on its [Permissions](#permissions){.link} and [Rules](#rules){.link}. To the right of the passphrase is a button to copy it to your clipboard for easier sharing with others. As the passphrase is necessary for joining a board or list and decrypting messages, if you want to share a board with someone, but don't want to share it via a list, you must provide the user with the passphrase.

Additionally, you may use non-default Message, Attachment, and Steg PGP passphrases that are used to decrypt their respective content. If you want added security for your community, generate different (i.e. non-default) PGP passphrases and share them with those you share your board/list passphrase with.

### Message PGP Passphrase

This is auto-populated with a passphrase common to all users who initially join a board. It can be changed locally by any user. Doing so creates a 'parallel board' wherein the user sends all subsequent posts encrypted with a new symmetric PGP passphrase. Only recipients who have also changed their passphrase to this non-default one will be able to see these posts, but conversely, the user who has changed their passphrase will no longer be able to see posts encrypted with the default or any other passphrase except the one they have set in this field.

### Attachment PGP Passphrase

Note: Only applicable to boards

This is auto-populated with a passphrase common to all users who initially join a board. It can be changed locally by any user. Only recipients who have also changed their passphrase to this non-default one will be able to decrypt these attachments, but conversely, the user who has changed their passphrase will no longer be able to decrypt attachments encrypted with the default or any other passphrase except the one they have set in this field.

### Steg PGP Passphrase

Note: Only applicable to boards

This is auto-populated with a passphrase common to all users who initially join a board. It can be changed locally by any user. Doing so creates a 'parallel steg board' wherein the user sends all subsequent steganographic posts encrypted with a new symmetric PGP passphrase. Only recipients who have also changed their passphrase to this non-default one will be able to see these steganographic posts, but conversely, the user who has changed their passphrase will no longer be able to see steganographic posts encrypted with the default or any other passphrase except the one they have set in this field.

### Owner Addresses

Owner addresses have the highest [Permissions](#permissions){.link} of any users and can be set during [Board and List Creation](#board-and-list-creation){.link}. Addresses listed where which you control are displayed in a green font color.

### Admin Addresses

Admin addresses have the next highest [Permissions](#permissions){.link} after owners and can be set during [Board and List Creation](#board-and-list-creation){.link}. Currently, the only special abilities Admins have over regular users are to delete threads and posts. Addresses listed where which you control are displayed in a green font color.

### User Addresses (only applicable to private boards)

User addresses have no [Permissions](#permissions){.link}, though they can locally delete posts. Applicable only to private boards, user addresses are set during [Board and List Creation](#board-and-list-creation){.link}. For public boards, any address (that is not an owner or an admin address) can function as a user address. Addresses listed where which you control are displayed in a green font color.

### Restricted Addresses

Restricted Addresses are prevented from posting to boards or modifying lists and are set during [Board and List Creation](#board-and-list-creation){.link} of public boards. Restricting addresses is useful if you wish to create a public list with *Requires Identity to Post* set and have all your other board and list addresses added to this *Restricted Addresses* list. This forces users to create an address (either an Identity or a board/list) in order to post or modify the list. Because the user is forced to create a new address, owner/admin are able to ban users. Addresses listed where which you control are displayed in a green font color.

### Options - Custom CSS

Here you can allow or disallow custom CSS set by the board/list Owner. **Be very careful and review all CSS before allowing as custom CSS presents a significant security attack vector.** If the Owner changes the CSS after you allow it, this setting will be switched automatically back to disallow until you review and allow the new custom CSS.

### Options - Leave Board/List

This allows you to leave the current board or list. You can always rejoin by entering the passphrase again or selecting **Join** from a list. Keep in mind that when leaving a board, all posts are deleted. Therefore, if you rejoin the board, you will not be able to retrieve any posts who's TTL has expired.

## Owner Options

If you are an Owner of a board or list, this dropdown menu will appear. It allows the Owner to change parameters of the board/list.

### Addresses

Here you can set the Admin, User, and Restricted addresses after the board/list creation, separated by commas.

### Custom Banner Image

Here you can upload a custom banner image with a maximum size of 1200 px width and 400 px height.

### Custom Spoiler Image

Here you can upload a custom spoiler image with a maximum size of 250 px width and 250 px height.

### Long Description

Here you can set a longer description that can also include text formatting and functions.

### Word Replacements

Here words can be set that will be replaced when a user makes a post.

### Custom CSS

Here custom CSS can be set that will affect all users. Due to the ability of CSS to pose a security risk, each user must allow any custom CSS the Owner sets.

# Rules

Rules are certain requirements of a board or list that are set by the Owner, or of a thread that are set by the poster.

## Board/List Rules

### Require Proof of Work (POW) to Post

Additional POW can be required to post to a board. This makes spamming more unlikely, as it becomes very costly to send a lot of messages. For Hashcash, to solve the POW challenge with a mid/high range CPU, it may take ~5 seconds at a difficulty of 20, ~15 sec at 21, and ~30 sec at 22. Repetitions can also be used to make POW times between users more consistent. This will solve multiple POW challenges at the specified difficulty. You can check the frontend log after making a post to see when POW completes and how long it took.

The difficulty and repetitions can be used to calculate a single value that can be used to compare post POW. (2^Difficulty)*Repetitions will yield a single value that is used to determine if the minimum amount of POW has been completed and for sorting posts by POW. For instance, POW with a difficulty of 18 and 2 repetitions is equivalent to POW with a difficulty of 19 and 1 repetition. Therefore, if a Board or Thread requires posts to complete a minimum POW with a difficulty of 18 and 2 repetitions, the difficulty and repetition combination must meet or exceed that specified minimum.

### Automatic Wipe

Set a start time (epoch timestamp) and interval for when all content on the board or list is deleted for all users.

### Require Identity to Post

Require that all posts originate from an address that is not the board or list address. This doesn't necessarily mean you need an identity to post, as other boards and list addresses can be used as long as they are not on the restricted list. Board owners can add restricted addresses even after board creation occurs, however this does not change the board passphrase.

### Restrict Thread Creation to Owners, Admins, and Thread Creation Users

Only the addresses added as an Owner, Admin, or Thread Creation Users to the Public or Private Board are permitted to create threads on the board. Regular users will still be able to post replies to a thread on the board (unless restricted elsewhere), but will not be able to create new threads.

### Thread Creation Users

When Restrict Thread Creation is enabled, te only users of the board that will be able to create new threads will be Owners, Admins, and any additional addresses added to this list. The list should be addresses separated by commas.

### Allow Lists to Store PGP Passphrases

When enabled, any board or list added to this list will also send the currently-set PGP passphrases (Message PGP passphrase for Lists and Message, Attachment, and Steg PGP passphrases for Boards). This allows a list to contain boards/lists with non-default PGP passphrases set and easily share them without having to supply the PGP passphrases separately from the list. When the user clicks Join from the list, the custom PGP passphrases (when the board/list was added to the list) are populated for that board/list on the following join page. If a list Owner wants to change the PGP passphrases associated with a board/list already on the list, just remove the board/list from the list, change the board/list PGP passphrases, and add the board/list again and the list will now contain the board/list with the new PSP passphrases. 

## Thread Rules

### Sort Replies by POW

Instead of replies being sorted by timestamp, the amount of POW will determine the reply position, with a post that conducted a greater amount of POW appearing closer to the OP.

### Require Proof of Work (POW) to Reply

Similar to the Board Rule Require Proof of Work (POW) to Post, this rule requires replies conduct a minimum amount of POW to post a reply to a thread. If I post doesn't meet the minimum, it will not appear on the thread.

# Identities

Identities are addresses that only you have the ability to control. The passphrase used to create the address will always create the same address. This means you can share the passphrase with other people, they will have the ability to post from the same address. To create an identity address, simply click the **Identities** link and enter a passphrase and a label. The identity will appear in the list with options to rename or delete it. There is no limit to the number of identities you can create. The label you choose will appear next to its address to indicate it's one of your identities. This label is only stored locally and will only be visible to you. Everyone else will only see the address.

Not every circumstance demands that you use an identity address to post to a board or modify a list. Unless a board/list requires specific addresses (e.g. public boards which have the rule *Require Identity to Post* enabled), you can use the address of the board/list itself. This can be considered an anonymous way to use BitChan, as all posts to a board are coming from the board's own address that every member of the board/list has access to.

Note: you cannot use a board/list passphrase as an identity passphrase.

## Mailboxes

Mailboxes allow identity-to-identity communication. You will have a mailbox for every identity you control. The link to the mailbox is found at the bottom of every page and includes a count of your unread messages. When you go to the mailbox, you will see a **Compose Message** link and a list of your identities with their labels and unread message count. Clicking the **Compose Message** link will bring you to the mail composition page. Clicking any of your identity links will bring you to that identity's mailbox. A mailbox contains inbox and sent folders.

Since board and list addresses are indistinguishable from identity addresses, there's nothing preventing a message being sent to a board or list address. This will merely cause BitChan to discard the received message, as it's not properly formatted to be interpreted by the board/list. However, if a user has another instance of Bitmessage running and has joined a chan using the board/list passphrase, the messages can be received and read. This is not a recommended use of the BitChan messaging platform, but only included here to allow the user to understand there exists the possibility you may be sending a message to a non-identity address for which there is no mechanism to allow it to be read within BitChan. When considering messaging an address on BitChan, understand there exists the possibility you will be messaging a non-identity address. Therefore, it may be beneficial to ask whether the address you desire to message is an identity, ask specifically for an identity address to message, or provide your own identity address and request a message be sent to it to initiate communication.

# Address Book

When you find an address that you want to associate with a name you can add it to the address book with a label. To do this, locate and click the arrow to the right of the address in a post header, select *Add to Address Book*, enter a label, then select *Save*. You can access the address book at any time by clicking the *Address Book* link, where you can add, rename, and delete address book entries. Alternatively, a user can post an identity using the [identity]...[/identity] formatting tags. When you receive a message which contains a new, previously un-added identity formatted in this way you will see an option to 'Add to Address Book'. Clicking this link will allow you to add a label and include the identity in your address book.

By default, the BitChan Developer address will be entered in your address book so you can identify official communications.

# Configuration

The configuration page contains configuration options and functions such as exporting.

## General Settings

### Enable Maintenance Mode

Maintenance mode prevents new posts from being made or automatic downloads from starting. This allows for a safe restart of the server, for instance in if an upgrade needs to occur, without the possibility of interrupting a post or download. Maintenance mode can be enabled, a short wait period to allow any posts or downloads to complete, then an upgrade or server restart can safely be performed.

### Theme

The theme can be changed to affect the text style on pages. The following themes are available:

- Dark: a dark color theme
- Classic: A red theme, similar to Yotsuba
- Frosty: A blue theme, similar to Yotsuba B
- Console: Another dark theme

### Max Home Page Updates

When a list is updated or a new post is made, that list/board jumps to the top of the home page. This option sets the maximum number of boards or lists to show. 

### Attachment Auto-Download Max Size (MB)

When a post is made with an attachment that has been uploaded to an external upload site or torrent via i2p, users that wish to view the attachment must download that encrypted file. By default, auto-downloading is disabled (this setting set to 0 MB) and a user desiring to acquire the attachment(s) must press the Allow Download button on the post. This setting allows you to auto-download attachments at or below the set file size, in MB.

### Attachment Extraction Max Size (MB)

Because compressed/encrypted files can be of a size significantly less than the decompressed/decrypted file size, this option prevents an exploit whereby a very large post attachment can be made. For example, a 100 GB file containing a repeating "0" character is a mere ~200 KB when compressed/encrypted. If this 100 GB file were to be added as a post attachment, the header of the file to be downloaded would only return ~200 KB. Only upon decompressing/decrypting will the true file size be revealed. This option sets a limit for how large the decompressed/decrypted post attachment file size can be. This setting also restricts the size of attachments when creating posts, which can be useful if running a public kiosk to limit the total attachment size.

### Automatically Start I2P BitTorrent Downloads for My Posts

When enabled, posts created with your BitChan instance will have I2P BitTorrent attachments automatically downloaded. This will automatically start your torrent seeding and display attachments for the post as soon as the post is received. When disabled, you must manually select Allow Download before the torrent starts seeding. Keep in mind that for others to get the attachments for your post, you must seed, therefore it is recommended to keep this enabled. If you're running a public kiosk, it is recommended to disable this option and set Attachment Auto-Download Max Size to manage automatic downloads.

### Allow connecting to upload site to verify post attachment size

Permit connecting (through tor) to upload sites to verify post attachment size. When a post arrives that indicates it has attachments on an external upload site, it also indicates what the size is. If this message was tampered with, it could indicate a smaller size than it actually is, which could trigger your auto-download to kick in, when in fact it could be much larger. File size checking will verify the file size before attempting an auto-download. If you allow file size checking, BitChan would recognize its true size, update the size displayed to the user and not auto-download if it's above the auto-download limit. At that point the user can be properly informed of the true size before using the Allow Download button or not.

If you suspect that someone might want to log your tor IP by forcing you to request a file size from an external upload site, then you can disable this. Of course, if your **Attachment Auto-Download Max Size** is above 0, then you may be tricked into downloading a massive file. As the download progresses, if the downloaded size exceeds the set limit, the download will be aborted. These are the challenges and trade-offs when dealing with a zero-trust distributed network.

### Allow connecting to get book quotes

Permit connecting (through tor) to get random book quotes for #stich and #godsong in posts. The #stitch and #godsong functions require connecting to websites and thus go outside the Bitmessage network. Disable this option to prevent connecting to the websites associated with these functions. If disabled, posts which contain these functions will not be populated with the formatted material, and instead will simply show "#stitch" or "#godsong".

### Never allow auto-download of unencrypted attachments

If a post has unencrypted attachments from upload sites, always require the Allow Download button to be used to download them. Enable this option if you don't want to auto-download any unencrypted file regardless of your **Attachment Auto-Download Max Size** setting.

### Remove unencrypted as attachment option

Allow "Unencrypted" as an encryption option for post attachments.

### Automatically download from unknown upload sites

BitChan comes with a number of upload sites by default that may be used to provide attachments for messages. However, because it is unknown whether these upload sites will exist in the future, users may add and use their own upload sites. Therefore, to ensure that future users can obtain these new upload site settings from other users posting with attachments, the information for where and how to download an attachment is contained within the message itself. When a message is received with an attachment and the upload site settings within the message are not currently saved to BitChan, you can easily save those settings to your database via a link that appears on the message. To give the user more control over what attachments are automatically downloaded, BitChan by default will not automatically download attachments from an upload site that is within a message if it doesn't already exist in the BitChan database. To download attachments from such a message, select the link to save the upload site settings, then manually start the download. Once the settings have been saved to the BitChan database, and if your other auto-download settings allow it, any attachments from subsequent messages that are received will be automatically downloaded since you have reviewed and acknowledged the upload site settings by saving them to the database. If you would like to override this feature and allow automatic downloading of attachments from upload sites that are not saved in the database, check this option.

### Automatically delete sent Identity messages

Any message you send from an Identity address stays in your mailbox unless it gets deleted. This setting automatically deletes all of these messages.

### Show Debug Information for Boards/Threads/Posts

This will show the entire database table entry for boards/threads/posts in an accordion. If kiosk is enabled, must be an Admin.

### Post Timestamp Use

This will determine which timestamp to use to sort posts, threads, and boards when order is considered.

### Threads Per Page on Board Page

The number of threads to display per page on board pages.

### Threads Per Page on Overboard Page

The number of threads to display per page on the overboard page.

### Threads Per Page on Catalog Page

The number of threads to display per page on catalog pages.

### Results Per Page on Recent Page

The number of posts to display per page on the recent page.

### Results Per Page on Search Page

The number of results to display per page on the search page.

### Results Per Page on Mod Log Page

The number of results to display per page on the mod log page.

### Home Page Message

This is the message that will appear on the home page. HTML is allowed.

### Template HEAD HTML

This is HTML that will be inserted into the template's \<HEAD\>. Useful for easily adding CSS or Javascript that gets applied to all pages.

### Template BODY HTML

This is HTML that will be inserted into the template's \<BODY\>. Useful for applying certain styles to all pages when HTML needs to be inserted in the \<BODY\> of all pages, such as an image overlay that you want to be displayed on every page.

## Bitmessage Settings

Bitmessage can be partly configured from BitChan. If these settings change, bitmessage will be restarted for the changes to take effect.

### Bitmessage Connections

Set how bitmessage connects to peers. If desiring to use tor, keep in mind that you may need to initially set Outgoing Connections to use the clearnet to build up a list of hosts prior to setting it to use Tor, otherwise the bitmessage tor bootstrap address may take an incredibly long time to establish an initial connection.

The installation procedure provides a version of knownnodes.dat that has aggregated many reliable hosts to make an initial connection to the bitmessage network. Alternatively, you can copy the contents of your own knownnodes.dat with your own bitmessage to BitChan's /usr/local/bitchan/bitmessage/knownnodes.dat (especially if bootstraping is not occurring in a timely manner).

Here are the keys.dat settings for each option (from [Bitmessage FAQ: How do I setup Bitmessage as a hidden service on Tor](https://wiki.bitmessage.org/index.php/FAQ#How_do_I_setup_Bitmessage_as_a_hidden_service_on_Tor)):

In: Clearnet<br/>Out: Clearnet | In: Tor + Clearnet<br/>Out: Clearnet | In: Tor<br/>Out: Clearnet
---|---|---
socksproxytype = none<br/>onionhostname = none | socksproxytype = none<br/>onionhostname = abcdefgh.onion<br/>onionport = 8444<br/>sockslisten = True | socksproxytype = none<br/>onionhostname = abcdefgh.onion<br/>onionbindip = 127.0.0.1<br/>onionport = 8444<br/>sockslisten = False |

In: Clearnet<br/>Out: Tor | In: Tor + Clearnet<br/>Out: Tor | In: Tor<br/>Out: Tor
---|---|---
socksproxytype = SOCKS5<br/>onionhostname = none<br/>sockslisten = True | socksproxytype = SOCKS5<br/>onionhostname = abcdefgh.onion<br/>onionport = 8444<br/>sockslisten = True | socksproxytype = SOCKS5<br/>onionhostname = abcdefgh.onion<br/>onionbindip = 127.0.0.1<br/>onionport = 8444<br/>sockslisten = False |

If MiNode is selected, MiNode will act as a bridge between Bitmessage and peers. This is how Bitmessage can communicate over I2P.

### Only Allow Bitmessage to Connect to Onion Services

If tor is permitted to be used for incoming/outgoing connections, bitmessage can be forced to only connect to onion addresses.

## Kiosk Settings

Kiosk mode allows BitChan users to turn their local instance into be accessible from a Tor Hidden Onion Service or Hidden I2P Service. The kiosk operator can customize who can access the service and what they can do. Operators can grant kiosk privileges such as administration rights, turn captcha on or off as well as a number of other alterations.

### Enable Kiosk Mode

Toggle kiosk mode on or off.

### Require Users to Log In

Enabling this setting forces kiosk users to log in to use the service. The operator can add credentials on the /configure page, next to "Enable Kiosk Mode", using the link "Kiosk User Management"  Ensure you have at least one Admin user defined before enabling this option, otherwise you may lose access. If kiosk mode is enabled and you are unable to access the UI, see the Kiosk Recovery User section at the top of config.py to fix your issue.

### Allow Users to Post

Allow users to post on boards. Turn the kiosk into read-only by enabling this setting.

### Allow Users to Perform Additional Proof of Work for Posts

Allow users to perform additional proof of work (POW)  to be performed for posts. Warning, this can allow DOS attacks on a kiosk.

### Allow Users to Encrypt PGP Messages in Posts

Allow users to encrypt or sign PGP messages in posts.

### Disable Bitmessage as a Post Upload Method

Sending large posts require more computational power to perform proof of work (POW) than smaller messages, which increases the time for a post to send and ties up CPU resources while POW is being conducted. By disabling Bitmessage as an attachment method, you can prevent users of a kiosk from using this CPU-intensive Upload Method.

### Disable I2P Torrent as a Post Upload Method

Prevent users of a Kiosk from using I2P BitTorrent as a post attachment upload site.

### Allow Users to Initiate Post Downloads

Used in tandem with the **Attachment Auto-Download Max Size**, preventing kiosk users from downloading attachments which exceed the maximum auto-download size can help prevent you kiosk's hard drive from getting filled up too fast. Only enable this setting if you are sure large downloads are not a problem.

### TTL Option

Force posts to use a specific Time To Live (TTL) or allow the user to set the TTL with a maximum.

### TTL Value

The custom TTL, in seconds, when forcing a specific TTL or setting a maximum TTL. Must be between 3600 and 2419200 seconds.

### Post Refractory Period (seconds)

This setting determines how frequently the kiosk as a whole can post. All users are simultaneously restricted by this setting. If, for example, the setting is set to 30 seconds and kiosk user A posts at time 00:00, and then kiosk user B tries to post a time 00:29, he will be prevented from doing so.

### Maximum Login Attempts

Sets the maximum kiosk login attempts before a user is banned.

### Login Ban Length (seconds)

Sets the login ban time in seconds.

### Only Kiosk Admins Can View Mod Log

When kiosk mode is enabled, only Admins can view the Mod Log.

## Security Settings

### Required Captcha to Post

If you notice or fear abuse of your kiosk you can require a captcha to be filled out for each post.

### Require Verification to Access

Each user is assigned a session ID when using the kiosk. Enable 'Require Verification to Access' if you want to force a captcha to be filled out before verifying a user's session.

### Enable Page Load Rate-Limiting

Enabling this setting will help to prevent denial of service type abuse.

### Maximum Requests Per Period

Enabling this setting will help to prevent denial of service type abuse.

### Rate Limit Period (seconds)

Enabling this setting will help to prevent denial of service type abuse.

### What to do when a Post/Thread is Remotely Deleted

When a post or thread is remotely deleted, you can choose to delete the post contents (including attachments), or merely hide it (allowing it to be unhidden at a later time).

### Disable Downloading Attachments from Upload Sites

If a post is received with attachments using an upload site, the attachments will not be downloaded.

### Disable Downloading Attachments from I2P Torrents

If a post is received with attachments using an i2p torrent, the attachments will not be downloaded.

### How Long (Days) to Allow I2P Torrents for OP Posts

If i2p torrent is enabled as a download method, how long should be waited after the original post to a thread is received before deleting the torrent. This is not the duration after the torrent begins seeding, but the duration after the torrent is initially started (since seeding may never occur). Therefore, at a minimum, you must account for the estimated time it would take to download the content.

### How Long (Days) to Allow I2P Torrent for Reply Posts

If i2p torrent is enabled as a download method, how long should be waited after a reply to a thread is received before deleting the torrent. This is not the duration after the torrent begins seeding, but the duration after the torrent is initially started (since seeding may never occur). Therefore, at a minimum, you must account for the estimated time it would take to download the content.

## RSS Settings

If hosting a Kiosk on a tor hidden service or I2P eepsite, an RSS can be enabled to generate a feed of all posts, board posts, and thread posts.

### Enable RSS Feeds with Tor URLs

Enable an RSS feed to be generated, with URLs generated using a tor address.

### Enable RSS Feeds with I2P URLs

Enable an RSS feed to be generated, with URLs generated using an i2p address.

### Tor BitChan URL

The tor address to use when generating URLs in the tor RSS feed.

### I2P BitChan URL

The tor address to use when generating URLs in the I2P RSS feed.

### Maximum Posts per Feed

How many posts to include in each feed. RSS URLs can have ?last=x appended to them, with x being an integer between 1 and the maximum set number fo posts per feed, and the feed will be reduced to that value.

### Maximum Character Limit per Post

The character limit that posts be truncated.

### Use HTML Posts

Enable HTML in posts. HTML posts will already be truncated based on popup HTML settings. Otherwise, posts will be plain text truncated to the RSS character limit specified.

### Rate Limit: Number of Requests

The maximum number of RSS requests allowed per time period, before further requests are denied.

### Rate Limit: Time Period

The time period to measure when determining if the RSS request rate needs to be limited.

## Export

Backups of BitChan information can be performed for boards/lists, identities, and the address book, in comma-separated value (CSV) format. The following is the information that is backed up:

- **Export Boards/Lists**
    - board or list type
    - label
    - description
    - access
    - address
    - passphrase
- **Export Identities**
    - label
    - address
    - passphrase
- **Export Address Book**
    - label
    - address

**Note: This does not backup board posts or items on lists.**

## Post Attachment Upload Sites

Here is a list of all current 3rd party upload sites that your instance of BitChan can use for transferring post attachments from one BitChan instance to another. You can edit, add or delete from this list. If a user posts with an upload site that is not in this list, a link will appear in the message header (as a hyperlinked 'a') that will bring you to a page allowing you to add the new host to your list. In place of the 'a', a 'v' will appear if the host is already on your list, allowing you to view or edit the host configuration. Adding or deleting entries on this list will affect the options in the 'Upload Method' dropdown menu when authoring a post. Disabling an entry will prevent it from being visible or used when Kiosk Mode is enabled.

## Custom Flags

BitChan comes with national flag images, but you can also add your own. The name you use will appear as a tooltip when a user hovers over your custom flag in a post. Flags can only be added if they meet certain criteria:

- Maximum size of 3.5 KB
- Maximum width of 25 pixels
- Maximum height of 15 pixels

When composing a message, custom flags will appear at the top of the flag dropdown menu with the prefix **Custom**.

## Tor Hidden Onion Service

A hidden tor onion services (v3) can be enabled to allow connecting to your BitChan install via an .onion address using tor browser. If enabling a random address, a random onion address will be generated and displayed. You can also provide a zip file containing credentials for hosting a custom onion address that you previously generated. This can be beneficial if you want to enable Kiosk Mode to allow anonymous access without exposing your IP address. See the README for more information about the benefits of setting up a tor hidden onion service on a virtual private server.

## Hidden I2P Service (eepsite)

A hidden I2P service can be used to create a tunnel to your BitChan install via an .i2p address over the I2P network. This can be beneficial if you want to enable Kiosk Mode to allow anonymous access without exposing your IP address.

Follow these instructions to set up an I2P tunnel to allow access to your BitChan install:

1. Bring the docker containers down with `cd BitChan/docker && sudo docker compose down`
2. Delete the I2P volume to allow reconfiguring the tunnels and i2pd config files: `sudo rm -rf /usr/local/bitchan-docker/i2pd`
3. Open Bitchan/docker/i2pd/Dockerfile and uncomment the COPY line that copies tunnels.conf to the i2pd volume.
4. If you have a tunnel private key file, you can uncomment the COPY line that copies that key file to the i2pd volume. Make sure the file name is correct in Dockerfile and tunnels.conf, and place that file in BitChan/docker/i2pd/ prior to building. You can also place this file in the volume directory /usr/local/bitchan-docker/i2pd as well.
5. Build and bring the containers back up: `cd BitChan/docker && sudo make daemon`
6. Open a browser to http://172.28.1.6:7070 to open the i2pd webconsole to view your I2P Tunnels and determine your .i2p address.
7. After the tunnel has started and peers have connected, your BitChan install will be accessible at that .i2p address.
8. You can register a short i2p address with a jump server, otherwise you can give out the b32 address for people to connect to.

Additionally, you can use 172.28.1.6:4444 as an HTTP proxy in your browser to connect to I2P sites and port 4447 as an i2p SOCKS proxy.

Warning: If your server IP address is publicly-accessible, be sure to change the default credentials in i2pd.conf and/or comment the i2pd port 7070 in docker-compose.yaml and rebuild the containers, to prevent potential unauthorized access.

## Board and List Options

Individual boards and lists can have additional attributes set, including: Unlisted, Restricted, Hide Passphrases, and Read Only. These settings are only really useful when Kiosk Mode is enabled, and allow for certain restrictions to be placed on boards and lists that enable control over who can view and interact with them. Note that Global Admins can always bypass these restrictions.

### Unlisted

Unlisted boards/lists will not appear on any public page but are still accessible, if you know the URL to access it.

### Restricted

Restricted boards/lists will not appear on any public page but will not be able to be accessed, even if the URL is known, unless you are a Board, List, or Global Admin. Note that this restriction is different from a Board/List Restricted User, which is a user that is prevented from posting or altering a list.

### Hide Passphrases

When enabled, the board or list will not show passphrases in the Board or List Information. This is useful if you want to allow access a board or list but don't want others to be able to join the board/list in another BitChan instance.

### Read Only

Read Only boards and lists can only be viewed, unless you are a Board, List, or Global Admin.

# Kiosk Mode

A Kiosk Mode has been created that institutes a login and permission system to allow administration as well as anonymous posting, among other features. Admins can log in and perform any action. Non-logged in users can be allowed to only view or make posts. You can also allow non-logged in users to only view and provide one or more guest logins that permit posting. There are several more Kiosk Mode options outlined in BitChan/config.py and detailed in the manual. When used in conjunction with the integrated Tor Hidden Onion Service or Hidden I2P Service configurations, you can provide secure and anonymous access to your BitChan instance, so neither the host nor the clients can obtain any identifying information about each other.

# Status

A page to display status information about BitChan, Bitmessage and Tor. The status page can be accessed by clicking the Status link located at the top of most BitChan pages.

## BitChan Status

### Version

This is the current BitChan version that you are running.

### Status

This lets you know if BitChan is running or not.

### Total messages processed

A running sum of all messages BitChan has received which match the BitChan format.

### Current version messages

A running sum of all processed messages which match the same BitChan version that you are running.

### Older version messages (discarded)

A running sum of received BitChan messages which are older than the version you are running.

### Newer version messages (discarded)

A running sum of received BitChan messages which are newer than the version you are running. If you see this above 0, it indicates there is a newer version of BitChan available or someone has modified their version number.

### Post Upload Progress

The progress of any uploads which are in the process of being uploaded can be seen here. Uploaded files are periodically cleared from this list.

## Bitmessage Status

Here you can find diagnostic information about Bitmessage.

## Tor Status

### Request New BitChan Tor Identity

Here you can request a new BitChan Tor identity. This is useful if you think the Tor identity that BitChan uses to download from external file hosts has been blocked.

### Check Browser IP Address

This is just a convenient link to check your Tor IP for the browser you are using (assuming your browser is using Tor).

### Version

This shows the current version of Tor that Bitmessage and BitChan is using.

### Circuit Established

This indicates if Tor has established a circuit.

### Tor Circuits

Clicking this dropdown will allow you to examine the current Tor circuit that BitChan is using.

# Stats

This page displays global statistics. The number of total posts, thread and total attachment size are shown as well of charts which tabulate various activity metrics.

# Mod Log

This page logs board/list creation events, list alterations and administration events. You can filter the results to display remote moderation and failed moderation attempts.

# BC Log

This page displays output from the BitChan docker volume logs.

# Options Menu

Clicking the Options link will show a popup allowing custom user CSS and JavaScript as well as additional options, described below.

## CSS Tab

Enter custom CSS here. The CSS is added to a cookie.

## JS Tab

Enter custom JavaScript here. The JavaScript is added to a cookie.

## Options Tab

Locally change your theme here.

# Bug

This is a form to anonymously report bugs or send feature requests. Click the BitChan Log link to view and copy any relevant errors from the BitChan log for inclusion in your bug report.

# Donate

## Monero Address

```49KE6mo43c6DLuszW48ZkYG8x6KcxjhscY5KzsNLTqLk8Vw2gBaTnoggxfYLJnQ95zNuDpfFESYSFZoucYq5vWAjNrqHbhX```

# Developer Information

GitHub Repository: [github.com/813492291816/BitChan](https://github.com/813492291816/BitChan){.link}

Bitmessage Mail: address ```BM-2cWyqGJHrwCPLtaRvs3f67xsnj8NmPvRWZ```

Bitmessage Chan: passphrase "bitchan" without quotes, address ``BM-2cT6NKM8PZvgkdd8JZ3Z9r9u2sb3jbkCAf``

E-Mail (can only receive, no sending): [BitChan@mailchuck.com](mailto:bitchan@mailchuck.com){.link}

*This email is not considered secure and it's recommended to PGP-encrypt your messages when corresponding. If you would like a response, it's recommended to provide a Bitmessage address you can receive messages to and a PGP public key.*

PGP Public Key: [keys.openpgp.org/vks/v1/by-fingerprint/E90B33C4C0E73AF537F2C2E9B14DF20410E5A5BC](https://keys.openpgp.org/vks/v1/by-fingerprint/E90B33C4C0E73AF537F2C2E9B14DF20410E5A5BC){.link}
