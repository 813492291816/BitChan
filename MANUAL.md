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
  - [Creating Public Boards and Lists](#creating-public-boards-and-lists){.link}
  - [Creating Private Boards and Lists](#creating-private-boards-and-lists){.link}
- [Identities](#identities){.link}
  - [Mailboxes](#mailboxes){.link}
- [Address Book](#address-book){.link}
- [Configuration](#configuration){.link}
  - [Export](Export){.link}
  - [Custom Flags](#custom-flags){.link}
  - [Theme](#theme){.link}
- [Developer Information](#developer-information){.link}

# About

BitChan is a decentralized anonymous image board inspired by Bitboard and built on top of [Bitmessage](https://bitmessage.org){.link} with [Tor](https://www.torproject.org){.link} and [GnuGP](https://gnupg.org){.link}.

Bitmessage is a decentralized, text-based encrypted messaging application. It relies on public key encryption similar to PGP and decentralized message delivery, which due to the nature of every message being distributed to every client also provides plausible deniability (i.e. no one knows who the message was intended to go to). BitChan runs on top of Bitmessage to enhance its functionality and security. BitChan features boards for forum-like discussions with image and file sharing, lists to organize and share other boards and lists, along with a host of additional features to enhance posts and provide board/list management with the use of owner, admin, and user permissions. Boards and lists can be public or private, with or without owners or admins, allowing a full range of options from completely unmoderatable to strictly allowing only select addresses to post or modify list contents.

# Boards and Lists

Both boards and lists are built from channels, or chans, in Bitmessage. Each Bitmessage chan is an address that acts like an inbox that messages can be sent to. Message sent to a chan are encrypted so only members of that chan can decrypt and read them. To become a member of a chan, you must know the passphrase used to generate the chan's address. Anyone that has the passphrase that generates the address of the chan can decrypt the messages sent to the chan, allowing multiple people to read messages sent to the chan, and multiple people to send messages to the chan. You can use any address to send messages to the chan, including the same chan's address that's receiving it, your own identity addresses (personal addresses), or other chan addresses.

Although the functionality of boards and lists are very different, they both are operate on a simple chan. The messages received in chans are processed to determine if they originated from BitChan by their format and the decryptability of their contents. BitChan interprets the contents of the messages and presents the data in a meaningful way that extends the functionality of mere text communication.

Boards act as communication platforms for producing threads of one or more posts, with added functionality, including text formatting, file attachments (any format, with in-browser embedding for image, audio, and video), admin moderation, among others. Public boards allow anyone to post, including from the address of the board itself (an anonymous post) or from a different address. Private boards allow only specific addresses to post, while public boards allow any address to post (with some caveats). If a public board does not have an owner or admin set, it is completely unmoderatable and posts cannot be removed (unless an [automatic wipe rule](#automatic-wipe){.link} was set when it was created).

Lists act as a medium to compile a lists of other boards and lists that can be modified and shared with others. Users can join any of the boards or lists on the list. Any user can add to a public list, but only authorized users may add to a private list. Owners and admins may delete items from both public and private lists. If a public list does not have an owner or admin set, it is completely unmoderatable and can only grow in size (unless an [automatic wipe rule](#automatic-wipe){.link} was set when it was created).

Information about a board or list can be found in the "Information" dropdown box near the top of their page. This information includes:

***Address***

Every board and list has a unique and permanent Bitmessage address. To the right of the address is a button to copy it to your clipboard. This is provided for easier cross-linking (see [Functions](#functions)).

***Passphrase***

Every board and list has a unique and permanent passphrase that is used to generate the address of the board or list. This passphrase is required to join the board or list and decrypt the messages sent to the address. Any user with the passphrase can join the board or list and begin interacting with it, depending on its [Permissions](#permissions){.link} and [Rules](#rules){.link}. To the right of the passphrase is a button to copy it to your clipboard for easier sharing with others. As the passphrase is necessary for joining a board or list and decrypting messages, if you want to share a board with someone, but don't want to share it via a list, you must provide the user with the passphrase.

***Owner Addresses***

Owner addresses have the highest permissions of any users. These are typically considered the owners of the list or board. Addresses in this list that appear green indicate that you have these addresses either as an identity or belong to that addresses board or list. Another way of thinking about it is they are addresses in which you have the passphrase of, and those addresses can be used to interact with the board or list you're viewing the permissions of.

***Admin Addresses***

Admin addresses have the next highest permissions after owners. Currently, the only special abilities Admins have over regular users are to delete threads and posts.

***User Addresses***

For private boards and lists, addresses on the User Address list can post to boards or add to lists. If you don't have at least one address on this list, you are only able to view the board or list.   

***Restricted Addresses***

Restricted Addresses are prevented from posting to boards or modifying lists. This address list is useful if you wish to create a public list with *Requires Identity to Post* set and have all your other board and list addresses added to this *Restricted Addresses* list. This forces users to create an address (either an Identity or a board/list) in order to post or modify the list. Because the user is forced to create a new address, this allows the owner/admin to be able to ban users.

***Leave***

Leave the current board or list. You can always rejoin by entering the passphrase again or selecting **Join** from a list. Keep in mind that when leaving a board, all posts are deleted. Therefore, if you rejoin the board, you will not have it populate with messages that existed on the board prior to joining (note: when joining a board for the very first time, all unexpired messages prior to joining *are* retrieved).  

# Permissions

For both boards and lists, there can be Owner, Admin and User addresses specified. If you have an address that is an Owner or Admin of a board or list, you can perform special actions that affect all members. Normally, when a thread or post is deleted from a board, this occurs only locally on your computer. However, Owners and Admins have the ability to delete threads and posts for all users of the board. For private lists, Owners and Admins can delete list items and the changes will be reflected for all users of the list.

Owners of private boards and lists will see an **Owner Options** menu at the top of the page, where they can modify the parameters of the board or list. Additionally, when an Owner or Admin selects the dropdown menu next to a user's address or post ID, there will be additional options available to them. See the table, below, for what actions are available to each access level. Additionally, some actions may be restricted based on other settings of the board or list.

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

Posts are text-based messages on a board that can contain a file attachment. If the file attachment is a supported image or video, the media is displayed with the message. User-entered HTML is not allowed, but text can be stylized with various formatting tags. There are also several tags that provide the ability to execute functions (for example, dice rolls and coin flips, that because of the use of a seed, appear the same to all users). More about these functions can be found in [Text Modifications](#text-modifications){.link}.

## Composing Posts

There are a number of options available when composing a post, which include:

***From***

This list includes all available addresses which are controlled by you and allowed to post on the board. If the owner of the board has restricted certain addresses from posting and it's one you control, it will not appear in this list.

***Flag***

This list contains 258 nation flags to choose from. The selected flag will appear next to the From Address in the post header.

***Subject***

If your post is an original post (OP) you can provide a subject. The subject line can be a maximum of 64 characters. No formatting is allowed here.

***Comment***

This is where the body of your post is written, where several [Text Modifications](#text-modifications){.link} can be used.

***Post Formatting***

This menu contains buttons to facilitate formatting text in the comment. To use it, highlight text in the comment and press one of the buttons. This will surround the selected text with the formatting tags. More about formatting can be found in [Formatting](#formatting){.link}.

***Image/File***

Select a file attachment to upload with your post. You can attach any file type, but only certain types will display as embedded media (see [Supported File Types](#supported-file-types){.link}). Since Bitmessage only supports sending messages of up to ~300 KB, any attachments larger than this will need to use one of the alternate, external upload sites. All files have their filename obscured and their contents encrypted prior to upload. If the attached file is greater than 5 MB, it will be uploaded in the background and the post will be sent following a successful upload. The upload progress will be displayed on the status page.

***Image Spoiler***

Select this box to spoiler your image. Rather than automatically displaying the image on the post, a placeholder image will be displayed until the user clicks the image to display the original.

***Strip EXIF (JPG/PNG only)***

This option removes EXIF data from .jpg and .png files prior to posting to a board.

***Upload***

Select the desired file transfer method. Bitmessage is the most secure method of sending a file, but there is a ~300 KB limit due to the message size limitations of Bitmessage (and a drawback for sending large file sizes due to the required proof of work to send a message that significantly increases how long it takes to send your message). Several external upload sites are supported, and additional measures have been taken to ensure the privacy of your file when uploaded to these sites. First, the attachment is added to a compressed and password-protected ZIP archive. Then, the headers of the archive are taken out of the file, along with several random-sized segments at random places from the file, and inserted into the message transmitted over Bitmessage. The file is then uploaded to the external site, and once the file has been downloaded by the user, these pieces are placed back into the archive and the file is extracted. Additionally, and like all Bitmessage communication, all uploads and downloads are routed through tor.

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

**Audio**: .wav, .mp3, .ogg

**Images**: .jpg, .jpeg, .png, .gif, .webp

**Video**: .mp4, .webm, .ogg

## Steganography

Steganography is used to insert text messages into images attached to posts. A passphrase is used to PGP-encrypt the message being inserted into the image. You can use the default passphrase or set your own when creating or joining a board. If not using the default passphrase, be aware that any posts that contain an image with a message encrypted using the default passphrase will not be able to be read. That is, messages encrypted with a passphrase that's different than the one currently set to decrypt with will not be able to be read. Therefore, if using a non-default passphrase, others must also be using the same non-default passphrase as you if you want to communicate with them.

# Threads

Threads are collections of posts under a single subject that are displayed sequentially in the order in which they were received. The creation of a thread is based on the hash of a post that identified itself as an OP. Any post that identifies itself as an OP is placed into its own new thread. Any post that identifies itself as a reply and references the hash of a non-existent OP/thread is placed under an OP place holder. This prevents OP hijacking and other issues that can arise from messages being received out of order or otherwise containing malicious content.

# Board and List Creation

BitChan allows anyone to make and maintain boards and lists. Your board/list can be made

- Whenever
- For any reason and
- About anything

To create a board or a list go to the home page, click the **Create or Join** link and select the option that suits you:

- Create Public Board
- Create Private Board
- Create Public List
- Create Private List

Click **Next.** From here you can set Owner, Administrator, and User permissions by adding addresses from discovered or added boards, lists, identities, or manually added address book entries. Just tick their respective boxes. You can add additional addresses for each user type as comma separated values in the **Additional Addresses** field.

All boards and lists require both a label and description at a minimum.

***Label***

The label is a common name for the board or list. It corresponds to the url path normally seen on other imageboards (e.g. /fit/ in https://imageboard.com/fit/). Slashes '/' are not necessary when entering your label.

***Description***

The description is a few words which describes the general theme of the board.

***Owner Addresses***

Owner addresses have special abilities to moderate their board or list. This includes, but is not limited to, the ability to ban users, globally delete posts/threads, set custom CSS, set word replacements, modify address access, and set a custom banner image.

***Admin Addresses***

Admin addresses have a limited set of abilities to moderate a board or list. This includes the ability to delete posts/threads.

***User Addresses***

User addresses are those addresses that can only post or add to a list. This access level is only useful when creating a private board or list and you wish to give only specific addresses the ability to post or add to a list. This can be useful because you have the most control and can remove the addresses of users that cause problems on your board or list.

***Restricted Addresses***

Only available for public boards and public lists, restricted addresses are prevented form posting or modifying lists. When used in conjunction with **Require Identity to Post**, you can selectively ban individuals from posting or modifying lists.

***Extra String***

Since passphrases are used to create board and lists, it's crucial to use a unique passphrase to ensure the board or list you're creating is unique. Furthermore, since passphrases are generated based on the parameters of the board or list (label, description, addresses, etc.), it's possible for two users to generate the same passphrase, resulting in the same board or list. Therefore, in order to increase the likelihood of generating a unique passphrases, a user can add an extra string of characters to the end of their passphrase.

## Rules

Rules are certain requirements of a board or list that are set by the Owner.

### Automatic Wipe

Set a start time (epoch timestamp) and interval for when all content on the board or list is deleted for all users.

### Require Identity to Post

Require that all posts originate from an address that is not the board or list address. This doesn't necessarily mean you need an identity to post, as other boards and list addresses can be used as long as they are not explicitly restricted from doing so.

## Creating Public Boards and Lists

Public boards are the closest to an unmoderated board you can get on BitChan. Any address except those on the restricted address list can create threads and posts. Addresses can be restricted after board creation by the owner, but because of the freedom afforded by Bitmessage to create an arbitrary number of unique addresses, if your address is restricted, you can simply make another one.

Similarly for public lists, you can create a list to which any address except those on the restricted address list can add their own boards or lists to the public list.

## Creating Private Boards and Lists

By default, private boards and lists prevent users from posting unless given access. This access is enabled through the Owner, Admin, and User address lists set at the time the board or list is created. Additionally, these access lists can be changed after the board or list is created.

# Identities

Identities are addresses that only you have the ability to control. The passphrase used to create the address will always create the same address. This means you can share the passphrase with other people and they will have the ability to post from the same address. To create an identity address, simply click the **Identities** link and enter a passphrase and a label. The identity will appear in the list with options to rename or delete it. There is no limit to the number of identities you can create. The label you choose will appear next to it's address to indicate it's one of your identities. This label is only stored locally and will only be visible to you. Everyone else will only see the address.

Not every circumstance demands that you use an identity address to post or modify a list. Unless a board/list requires specific addresses (e.g. public boards which have the rule *Require Identity to Post* enabled), you can use the address of the board/list itself. This can be considered an anonymous way to use BitChan, as all posts to a board are coming from the board's own address.

## Mailboxes

Mailboxes allow identity-to-identity communication. You will have a mailbox for every identity you control. The link to the mailbox is found at the bottom of every page and includes a count of your unread messages. When you go to the mailbox, you will see a **Compose Message** link and a list of your identities with their labels and unread message count. Clicking the **Compose Message** link will bring you to the mail composition page. Clicking any of your identity links will bring you to that identity's mailbox. A mailbox contains an inbox folder and a sent folder.

Since board and list addresses are indistinguishable from identity addresses, there's nothing preventing a message to be sent to a board or list address. This will merely cause BitChan to delete the message, once received, as it's not properly formatted to be interpreted by the board/list. However, if a user has another instance of Bitmessage running and has joined a chan using the board/list passphrase, the messages can be received and read. This is not a recommended use of the BitChan messaging platform, but only included here to allow the user to understand there exists the possibility you may be sending a message to a non-identity address for which there is no mechanism to allow it to be read within BitChan. Therefore, when considering messaging a user address on BitChan, understand there exists the possibility you will be messaging a non-identity address. Therefore, it may be beneficial to ask whether the address you desire to message is an identity, ask specifically for an identity address to message, or provide your own identity address and request it be messaged.

# Address Book

When you find an address that you want to associate with a name you can add it to the address book with a label. To do this, locate and click the arrow to the right of the name in a post, select *Add to Address Book*, enter a label, then select *Save*. You can access the address book at any time by clicking the *Address Book* link, where you can add, rename, and delete address book entries.

By default the BitChan Developer address will be entered in your address book so you can identify official communications.

# Configuration

The configuration page contains BitChan functions such as exporting comma separated lists of BitChan information, uploading, naming and deleting custom flags, and a theme selector.

## Export

Backups of BitChan information can be performed for boards/lists, identities, and the address book, in comma-separated value format. The following is the information that is backed up:

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

## Custom Flags

BitChan comes with the flags of 258 nations, but you can also add your own. The name you use will appear as a tooltip when a user hovers over your custom flag in a post. Flags can only added if they meet certain criteria:

- Maximum size of 3.5 KB
- Maximum width of 25 pixels
- Maximum height of 15 pixels

When composing a message, custom flags will appear at the top of the flag dropdown menu with the prefix **Custom**.

## Theme

The theme can be changed to affect the text style on pages. The following themes are available:

- Dark: a dark color theme
- Classic: A red theme, similar to Yotsuba
- Frosty: A blue theme, similar to Yousuba B

# Developer Information

GitHub Repository: [github.com/813492291816/BitChan](https://github.com/813492291816/BitChan){.link}

Bitmessage Address: ```BM-2cWyqGJHrwCPLtaRvs3f67xsnj8NmPvRWZ```

E-Mail (can only receive, no sending): [BitChan@mailchuck.com](mailto:bitchan@mailchuck.com){.link}

*This email is not considered secure and it's recommended to PGP-encrypt your messages when corresponding. If you would like a response, it's recommended to provide a Bitmessage address you can receive messages to and a PGP public key.*

PGP Public Key: [keys.openpgp.org/vks/v1/by-fingerprint/E90B33C4C0E73AF537F2C2E9B14DF20410E5A5BC](https://keys.openpgp.org/vks/v1/by-fingerprint/E90B33C4C0E73AF537F2C2E9B14DF20410E5A5BC){.link}
