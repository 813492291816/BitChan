<h1 align="center">BitChan Manual</h1>

- [About](#about){.link}
- [Boards and Lists](#boards-and-lists){.link}
- [Permissions](#permissions){.link}
- [Posts](#posts){.link}
  - [Composing Posts](#composing-posts){.link}
  - [Text Modifications](#text-modifications){.link}
    - [Formatting](#formatting){.link}
    - [Functions](#functions){.link}
  - [Supported File Types](#supported-file-types){.link}
  - [Steganography](#steganography){.link}
- [Threads](#threads){.link}
- [Board and List Creation](#board-and-list-creation){.link}
  - [Rules](#rules){.link}
    - [Automatic Wipe](#automatic-wipe){.link}
    - [Require Identity to Post](#require-identity-to-post){.link}
    - [Allow Lists to Store PGP Passphrases](#allow-lists-to-store-pgp-passphrases){.link}
  - [Creating Public Boards and Lists](#creating-public-boards-and-lists){.link}
  - [Creating Private Boards and Lists](#creating-private-boards-and-lists){.link}
  - [Board and List Information](#board-and-list-information){.link}
- [Owner Options](#owner-options){.link}
  - [Addresses](#addresses){.link}
  - [Custom Banner Image](#custom-banner-image){.link}
  - [Custom Spoiler Image](#custom-spoiler-image){.link}
  - [Long Description](#long-description){.link}
  - [Word Replacements](#word-replacements){.link}
  - [Custom CSS](#custom-css){.link}
- [Identities](#identities){.link}
  - [Mailboxes](#mailboxes){.link}
- [Address Book](#address-book){.link}
- [Configuration](#configuration){.link}
  - [Export](Export){.link}
  - [Custom Flags](#custom-flags){.link}
  - [Theme](#theme){.link}
- [Status](#status){.link}
- [Bug](#bug){.link}
- [Donate](#donate){.link}
- [Developer Information](#developer-information){.link}

# About

BitChan is a decentralized anonymous imageboard inspired by [Bitboard](https://github.com/michrob/bitboard){.link} and built on top of [Bitmessage](https://bitmessage.org){.link} with [Tor](https://www.torproject.org){.link} and [GnuPG](https://gnupg.org){.link}.

Bitmessage is a decentralized, text-based encrypted messaging application that runs on top of Bitmessage to enhance its functionality and security. It relies on public key encryption similar to PGP and decentralized message delivery, which, due to the nature of every message being distributed to every client, also provides plausible deniability (i.e. no one knows who the message was intended to go to). BitChan features boards for forum-like discussions with image and file sharing, lists to organize and share other boards and lists, and a host of additional features. Board/list management is possible via the application of owner, admin, and user permissions. Boards and lists can be public or private and with or without owners or admins, allowing a full range of options from completely unmoderatable to strict, where only select addresses are allowed to post or modify list contents.

# Boards and Lists

Both boards and lists are built on what Bitmessage calls chans (short for channels), each with an address that allows a public key to be derived from which messages can be encrypted. Within BitChan, messages sent to a board/list are further encrypted again so only members of that board with the proper credentials can decrypt and read them. To become a member of a board (or list), you must know the passphrase used to generate the Bitmessage address and the PGP passphrase(s) used to decrypt BitChan messages. Under normal circumstances, anyone that has the passphrase that generates the address of the board/list and the message PGP passphrase(s) can read the messages sent to it. Under the most relaxed board configuration, you can use any address to send messages to a board, including the same board's address that's receiving it (considered anonymous), your own identity addresses (personal address only you can send from), or other board/list addresses (addresses all members of those boards/lists can send from). More about board creation, configuration and permissions can be found in [Board and List Creation](#board-and-list-creation){.link}.

Although the functionality of boards and lists are very different, they both operate on Bitmessage chans. The messages received in chans are processed to determine if they originated from BitChan by their decryptability and their content. BitChan parses the contents of messages and presents the data in a meaningful way that extends the functionality of mere text communication.

Boards act as communication platforms for producing threads consisting of posts, with added functionality, including text formatting (color, style), multiple file attachments (with any extension and in-browser embedding of image, audio, and video), and admin moderation, among others. Public boards allow anyone to post, including from the address of the board itself (an anonymous post) or from a different address (similar to using tripcodes). Private boards allow only specific addresses to post. If a public board does not have an owner or admin set, it is completely unmoderatable and posts cannot be removed (unless an [automatic wipe rule](#automatic-wipe){.link} was set when it was created).

Lists act as a medium to compile a list of other boards and lists that can be modified and shared with others. Users can join any of the boards or lists on the list. Any user can add to a public list, but only authorized users may add to a private list. Owners and admins may delete items from both public and private lists. If a public list does not have an owner or admin set, it is completely unmoderatable and can only grow in size (unless an [automatic wipe rule](#automatic-wipe){.link} was set when it was created).

Information about a board or list can be found in the "Information" dropdown box near the top of their page. See [Board and List Information](#board-and-list-information){.link} for what is included.

# Permissions

For both boards and lists, there can be Owner, Admin, and User addresses specified. If you control an address that is an Owner or Admin of a board or list, you can perform special actions that affect all members. Normally, when you click a link for a thread or post to be deleted from a board, this occurs only locally on your computer. However, Owners and Admins have the ability to delete threads and posts for all users of the board. For private lists, Owners and Admins can delete list items and the changes will be reflected for all users of the list.

Owners of private boards and lists will see an [Owner Options](#owner-options){.link} menu at the top of the page, where they can modify the parameters of the board or list. Additionally, when an Owner or Admin selects the dropdown menu next to a user's address or post ID, there will be additional options available to them. See the table, below, for what actions are available to each access level. Additionally, some actions may be restricted based on other settings of the board or list.

Ability | Owner | Admin | User
--- | --- | --- | ---
Modify Access Addresses | X | | |
Set Custom Banner Image | X | | |
Set Custom CSS | X | | |
Set Word Replacements | X | | |
Global Post/Thread Delete | X | X | |
Ban Address | X | X | |
Delete from List | X | X | |
Post | X | X | X |
Add to List |  X | X | X |

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

***Images/Files***

Select up to 4 file attachments to upload with your post. You can attach any file type, but only certain types will display as embedded media (see [Supported File Types](#supported-file-types){.link}). Since Bitmessage only supports sending messages of up to ~300 KB, any attachments larger than this will need to use one of the alternate, external upload sites. All files have their filename/extensions obscured and their contents encrypted prior to upload. If the total size of the attachment(s) is greater than 5 MB, it will be uploaded in the background and the post will be sent following a successful upload. The upload progress will be displayed on the [Status](#status){.link} page.

Next to each of the 4 attachment fields is a checkbox for spoilering your image. Rather than automatically displaying the image on the post, a placeholder image will be displayed until the user clicks it to display the original. This option only works with image attachments. There is also an 'X' for removing a selected file attachment.

***Strip EXIF (JPG/PNG only)***

This option removes EXIF data from .jpg and .png files prior to posting to a board.

***Upload Method***

Select the desired file transfer method. Bitmessage is the most secure method of attaching a file, but only message (subject + comment + attachments + metadata) sizes of ~300 KB or less are permitted due to the size limitation of Bitmessage messages. Additionally, there is a drawback for sending large file sizes due to the required proof of work for sending Bitmessage messages. Sending large Bitmessage messages significantly increases how long it takes to send. External upload sites are supported, and additional measures have been taken to ensure the privacy of your file when uploaded to these sites. First, the attachment or attachments are zipped and encrypted with a random file name and extension. Then, the beginning and ends of the file, along with several randomly-sized segments at randomly-chosen locations in the file are removed, then uploaded to the external site. The random file parts are then sent with the message that's transmitted over Bitmessage. Once a user receives the post, the file is downloaded, the parts are inserted back into the file, then it's decrypted and unzipped. Additionally, and like all Bitmessage communication, all uploads and downloads are routed through tor.

***Upload Encryption***

Select which cipher and key bit length you want to use to encrypt your file attachments.

***Image to Insert Steg***

This dropdown lets you select an image into which you can insert a steganographic comment. This only works for JPG and PNG attachments.

***Steg Comment (JPG/PNG only)***

Enter any text you desire to hide in your image with steganography. Some images may not work due to limitations of the software or a characteristic of the particular image. You should receive an error if it's unable to be performed.

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

**Audio**: WAV, MP3, OGG

**Images**: JPG, JPEG, PNG, GIF, WEBP

**Video**: MP4, WEBM, OGG

## Steganography

Steganography is used to insert text messages into images attached to posts. A passphrase is used to PGP-encrypt the message being inserted into the image. You can use the default passphrase or set your own when creating or joining a board, or after board creation in the Board Information dropdown. If not using the default passphrase, be aware that any posts that contain an image with a message encrypted using the default passphrase will not be able to be decrypted/read. That is, messages encrypted with a passphrase that's different than the one currently set to decrypt with will not be able to be read. Therefore, if using a non-default passphrase, others must also be using the same non-default passphrase if you want to communicate with them. If you're being invited to a board with a non-default Steg Passphrase, you will typically be provided a non-default Steg Passphrase when you are provided the Board Passphrase used to join the board. 

# Threads

Threads are collections of posts under a single subject that are displayed sequentially in the order in which they were sent. The creation of a thread is based on the hash of a post that identifies itself as an OP. Any post that identifies itself as an OP is placed into its own new thread. Any post that identifies itself as a reply and references the hash of a non-existent OP/thread is placed under an OP place holder. This prevents OP hijacking and other issues that can arise from messages being received out of order or otherwise attempting to disrupt a thread by containing inauthentic metadata.

# Board and List Creation

BitChan allows anyone to create and moderate boards and lists. Your board/list can be made

- Whenever
- For any reason
- About anything

To create a board or list simply click the **Create or Join** link at the bottom of the page and select your desired option:

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

## Rules

Rules are certain requirements of a board or list that are set by the Owner.

### Automatic Wipe

Set a start time (epoch timestamp) and interval for when all content on the board or list is deleted for all users.

### Require Identity to Post

Require that all posts originate from an address that is not the board or list address. This doesn't necessarily mean you need an identity to post, as other boards and list addresses can be used as long as they are not on the restricted list. Board owners can add restricted addresses even after board creation occurs, however this does not change the board passphrase.

### Allow Lists to Store PGP Passphrases

When enabled, any board or list added to this list will also send the currently-set PGP passphrases (Message PGP passphrase for Lists and Message, Attachment, and Steg PGP passphrases for Boards). This allows a list to contain boards/lists with non-default PGP passphrases set and easily share them without having to supply the PGP passphrases separately from the list. When the user clicks Join from the list, the custom PGP passphrases (when the board/list was added to the list) are populated for that board/list on the following join page. If a list Owner wants to change the PGP passphrases associated with a board/list already on the list, just remove the board/list from the list, change the board/list PGP passphraess, and add the board/list again and the list will now contain the board/list with the new PSP passphrases. 

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

# Owner Options

If you are an Owner of a board or list, this dropdown menu will appear. It allows the Owner to change parameters of the board/list.

## Addresses

Here you can set the Admin, User, and Restricted addresses after the board/list creation, separated by commas.

## Custom Banner Image

Here you can upload a custom banner image with a maximum size of 650 px width and 400 px height.

## Custom Spoiler Image

Here you can upload a custom spoiler image with a maximum size of 250 px width and 250 px height.

## Long Description

Here you can set a longer description that can also include text formatting and functions.

## Word Replacements

Here words can be set that will be replaced when a user makes a post.

## Custom CSS

Here custom CSS can be set that will affect all users. Due to the ability of CSS to pose a security risk, each user must allow any custom CSS the Owner sets.

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

Here is a list of all current external host upload sites that your instance of BitChan can use to attach files to posts. You can edit, add or delete from this list. If a user posts with an upload site that is not on your list, a link will appear in the message header. It appears as a hyperlinked 'a' and clicking it will bring you to a page allowing you to add the host to your list. In place of the 'a' a 'v' will appear if the host is already on your list, allowing you to view or edit the configuration of this host. Adding or deleting entries on this list will affect the options seen in the 'Upload Method' dropdown menu.

## Custom Flags

BitChan comes with national flag images, but you can also add your own. The name you use will appear as a tooltip when a user hovers over your custom flag in a post. Flags can only be added if they meet certain criteria:

- Maximum size of 3.5 KB
- Maximum width of 25 pixels
- Maximum height of 15 pixels

When composing a message, custom flags will appear at the top of the flag dropdown menu with the prefix **Custom**.

## Theme

The theme can be changed to affect the text style on pages. The following themes are available:

- Dark: a dark color theme
- Classic: A red theme, similar to Yotsuba
- Frosty: A blue theme, similar to Yousuba B

# Max Home Page Updates

When a list is updated or a new post is made, that list/board jumps to the top of the home page. This option sets the maximum number of boards or lists to show. 

# Auto-Download Max Size

When a post is made with an attachment that has been uploaded to an external upload site, users that wish to view the attachment must download that file from the external upload site. By default, auto-downloading is disabled (set to 0 MB) and a user desiring to acquire the attachment(s) must press the Download button on the post. This setting allows you to auto-download attachments at or below the set file size, in MB.

# Status

Status information about BitChan, Bitmessage and Tor can be found here. The status page can be accessed by clicking the Status link located at the bottom of most BitChan pages.

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

# Bug

This is a form to anonymously report bugs or send feature requests. Click the BitChan Log link to view and copy any relevant errors from the BitChan log for inclusion in your bug report.

# Donate

## Monero Address

```49KE6mo43c6DLuszW48ZkYG8x6KcxjhscY5KzsNLTqLk8Vw2gBaTnoggxfYLJnQ95zNuDpfFESYSFZoucYq5vWAjNrqHbhX```

# Developer Information

GitHub Repository: [github.com/813492291816/BitChan](https://github.com/813492291816/BitChan){.link}

Bitmessage Address: ```BM-2cWyqGJHrwCPLtaRvs3f67xsnj8NmPvRWZ```

E-Mail (can only receive, no sending): [BitChan@mailchuck.com](mailto:bitchan@mailchuck.com){.link}

*This email is not considered secure and it's recommended to PGP-encrypt your messages when corresponding. If you would like a response, it's recommended to provide a Bitmessage address you can receive messages to and a PGP public key.*

PGP Public Key: [keys.openpgp.org/vks/v1/by-fingerprint/E90B33C4C0E73AF537F2C2E9B14DF20410E5A5BC](https://keys.openpgp.org/vks/v1/by-fingerprint/E90B33C4C0E73AF537F2C2E9B14DF20410E5A5BC){.link}
