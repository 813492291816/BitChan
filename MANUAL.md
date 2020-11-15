<h1 align="center">BitChan Manual</h1>

- [About](#about)
- [Boards and Lists](#boards-and-lists)
- [Permissions](#permissions)
- [Posts](#posts)
  - [Composing Posts](#composing-posts)
  - [Text Modifications](#text-modifications)
    - [Formatting](#formatting)
    - [Functions](#functions)
  - [Supported File Types](#supported-file-types)
- [Threads](#threads)
- [Board and List Creation](#board-and-list-creation)
  - [Rules](#rules)
    - [Automatic Wipe](#automatic-wipe)
    - [Require Identity to Post](#require-identity-to-post)
  - [Creating Public Boards and Lists](#creating-public-boards-and-lists)
  - [Creating Private Boards and Lists](#creating-private-boards-and-lists)
- [Identities](#identities)
- [Address Book](#address-book)
- [Developer Information](#developer-information)

# About

BitChan is a decentralized anonymous image board inspired by Bitboard and built on top of [BitMessage](https://bitmessage.org) with [Tor](https://www.torproject.org) and [GnuGP](https://gnupg.org).

BitMessage is a decentralized, text-based encrypted messaging application. It relies on public key encryption similar to PGP and decentralized message delivery, which due to the nature of every message being distributed to every client also provides plausible deniability (i.e. no one knows who the message was intended to go to). BitChan runs on top of BitMessage to enhance its functionality and security. BitChan features boards for forum-like discussions with image and file sharing, lists to organize and share other boards and lists, along with a host of additional features to enhance posts and provide board/list management with the use of owner, admin, and user permissions. Boards and lists can be public or private, with or without owners or admins, allowing a full range of options from completely unmoderatable to strictly allowing only select addresses to post or modify list contents.

# Boards and Lists

Both boards and lists are built from channels, or chans, in BitMessage. Each BitMessage chan is an address that acts like an inbox that messages can be sent to. Message sent to a chan are encrypted so only members of that chan can decrypt and read them. To become a member of a chan, you must know the passphrase used to generate the chan's address. Anyone that has the passphrase that generates the address of the chan can decrypt the messages sent to the chan, allowing multiple people to read messages sent to the chan, and multiple people to send messages to the chan. You can use any address to send messages to the chan, including the same chan's address that's receiving it, your own identity addresses (personal addresses), or other chan addresses.

Although the functionality of boards and lists are very different, they both are operate on a simple chan. The messages received in chans are processed to determine if they originated from BitChan by their format and the decryptability of their contents. BitChan interprets the contents of the messages and presents the data in a meaningful way that extends the functionality of mere text communication.

Boards act as communication platforms for producing threads of one or more posts, with added functionality, including text formatting, file attachments (any format, with in-browser embedding for image, audio, and video), admin modertion, among others. Public boards allow anyone to post, including from the address of the board itself (an anonymous post) or from a different address. Private boards allow only specific addresses to post, while public boards allow any address to post (with some caveats). If a public board does not have an owner or admin set, it is completely unmoderatable and posts cannot be removed (unless an [automatic wipe rule](#automatic-wipe) was set when it was created).

Lists act as a medium to compile a lists of other boards and lists that can be modified and shared with others. Users can join any of the boards or lists on the list. Any user can add to a public list, but only authorized users may add to a private list. Owners and admins may delete items from both public and private lists. If a public list does not have an owner or admin set, it is completely unmoderatable and can only grow in size (unless an [automatic wipe rule](#automatic-wipe) was set when it was created).

Information about a board or list can be found in the "Information" dropdown box near the top of their page. This information includes:

***Address***

Every board and list has a unique and permanent BitMessage address. To the right of the address is a button to copy it to your clipboard. This is provided for easier cross-linking (see [Functions](#functions)).

***Passphrase***

Every board and list has a unique and permanent passphrase that is used to generate the address of the board or list. This passphrase is required to join the board or list and decrypt the messages sent to the address. Any user with the passphrase can join the board or list and begin interacting with it, depending on its [Permissions](#permissions) and [Rules](#rules). To the right of the passphrase is a button to copy it to your clipboard for easier sharing with others. As the passphrase is necessary for joining a board or list and decrypting messages, if you want to share a board with someone, but don't want to share it via a list, you must provide the user with the passphrase.

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

Posts are text-based messages on a board that can contain a file attachment. If the file attachment is a supported image or video, the media is displayed with the message. User-entered HTML is not allowed, but text can be stylized with various formatting tags. There are also several tags that provide the ability to execute functions (for example, dice rolls and coin flips, that because of the use of a seed, appear the same to all users). More about these functions can be found in [Text Modifications](#text-modifications).

## Composing Posts

There are a number of options available when composing a post, which include:

***From***

This list includes all available addresses which are controlled by you and allowed to post on the board. If the owner of the board has restricted certain addresses from posting and it's one you control, it will not appear in this list.

***Flag***

This list contains 258 nation flags to choose from. The selected flag will appear next to the From Address in the post header.

***Subject***

If your post is an original post (OP) you can provide a subject. The subject line can be a maximum of 64 characters. No formatting is allowed here.

***Comment***

This is where the body of your post is written, where several [Text Modifications](#text-modifications) can be used.

***Post Formatting***

This menu contains buttons to facilitate formatting text in the comment. To use it, highlight text in the comment and press one of the buttons. This will surround the selected text with the formatting tags. More about formatting can be found in [Formatting](#formatting).

***Image/File***

This is where you can select a file attachment. You can attach any file type, but only certain types will display as embedded media (see [Supported File Types](#supported-file-types)).

***Image Spoiler***

Select this box to spoiler your image. Rather than automatically displaying the image on the post, a placeholder image will be displayed until the user clicks the image to display the original.

***Strip EXIF (JPG/PNG only)***

This option removes EXIF data from .jpg and .png files prior to posting to a board.

***Upload***

Select the desired file transfer method. BitMessage is the most secure method of sending a file, but there is a ~300 KB limit due to the message size limitations of BitMessage (and a drawback for sending large file sizes due to the required proof of work to send a message that significantly increases how long it takes to send your message). Several external upload sites are supported, and additional measures have been taken to ensure the privacy of your file when uploaded to these sites. First, the attachment is added to a compressed and password-protected ZIP archive. Then, the headers of the archive are taken out of the file, along with several random-sized segments at random places from the file, and inserted into the message transmitted over BitMessage. The file is then uploaded to the external site, and once the file has been downloaded by the user, these pieces are placed back into the archive and the file is extracted. Additionally, and like all BitMessage communication, all uploads and downloads are routed through tor.

***Steg Comment (JPG/PNG only)***

Enter any text you desire to hide in your image with steganography. Some images may not work due to limitations of the software or a characteristic of the particular image. You should receive an error if it's unable to be performed.

***Steg Passphrase***

The password to use to PGP-encrypt the message being inserted into the image. A default password is auto-populated here to allow for proof-of-concept testing of the steganography feature. In a future release, BitChan will allow the user to set the passphrase(s) to decrypt the message.

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

Public boards are the closest to an unmoderated board you can get on BitChan. Any address except those on the restricted address list can create threads and posts. Addresses can be restricted after board creation by the owner, but because of the freedom afforded by BitMessage to create an arbitrary number of unique addresses, if your address is restricted, you can simply make another one.

Similarly for public lists, you can create a list to which any address except those on the restricted address list can add their own boards or lists to the public list.

## Creating Private Boards and Lists

By default, private boards and lists prevent users from posting unless given access. This access is enabled through the Owner, Admin, and User address lists set at the time the board or list is created. Additionally, these access lists can be changed after the board or list is created.

# Identities

Identities are addresses that only you have the ability to control. The passphrase used to create the address will always create the same address. This means you can share the passphrase with other people and they will have the ability to post from the same address. To create an identity address, simply click the **Identities** link and enter a passphrase and a label. The identity will appear in the list with options to rename or delete it. There is no limit to the number of identities you can create. The label you choose will appear next to it's address to indicate it's one of your identities. This label is only stored locally and will only be visible to you. Everyone else will only see the address.

Not every circumstance demands that you use an identity address to post or modify a list. Unless a board/list requires specific addresses (e.g. public boards which have the rule *Require Identity to Post* enabled), you can use the address of the board/list itself. This can be considered an anonymous way to use BitChan, as all posts to a board are coming from the board's own address.

# Address Book

When you find an address that you want to associate with a name you can add it to the address book with a label. To do this, locate and click the arrow to the right of the name in a post, select *Add to Address Book*, enter a label, then select *Save*. You can access the address book at any time by clicking the *Address Book* link, where you can add, rename, and delete address book entries.

By default the BitChan Developer address will be entered in your address book so you can identify official communications.

# Developer Information

GitHub Repository: [github.com/813492291816/BitChan](https://github.com/813492291816/BitChan)

BitMessage Address: ```BM-2cWyqGJHrwCPLtaRvs3f67xsnj8NmPvRWZ```

E-Mail (can only receive, no sending): [BitChan@mailchuck.com](mailto:bitchan@mailchuck.com)

*This email is not considered secure and it's recommended to PGP-encrypt your messages when corresponding. If you would like a response, it's recommended to provide a BitMessage address you can receive messages to and a PGP public key.*

PGP Public Key:

```
-----BEGIN PGP PUBLIC KEY BLOCK-----

mQINBF+fVyMBEACph+HHLRIxQL4t+OaHgS1bmZgTbe92zGJoz1P6OENEgZDDgaVo
Dqg3+V3CFzrvp3u/vjAN+VpComxhuEVoWnkm8pJ/EdMYz3RV5ZgNBAmE+sJ7qXhN
apxao9Nq5lq4iAVENMd1BIvwSckveSuFs6DgKyqwpj/yavrKAcEM7uJLXuTdNS8J
xCB0ZcVw51AT6YS6K/YlsLuptVYI/IiY1z5UNG39lvryamSzPJSZqMQPSTX/plut
i5by3L0ne5yz1W10iZZevRLAe9lsV6jzi6g5gYwsItJRIAHRNhE5I98Q0Y6Vl9J4
5+pSrLEFtHH+LhBRIfGjNHDgA50vMJXQI+F8KQhXWf7NOcGTtXQTS23yAeEMRvQf
V1iahoGUzrm05a7AJcSTX83b22GRgFXpATr4QM5Fq0sS4BfYSYrj3aaAYDo8tg4G
qxHo3ZiJQvxwq730HyNfo/XRm5wpKQURdpPzVt/Q/7kNlMBdC67XjiAp0kskIEvz
hWZTH1GRU9Jf+ovzAhytXqqQdtLE0uOPW1XxthCa6tQbsFzSZwOkGsUtjEQ5KRVT
ZqkEKV6yFldQCNWH+pSyoM+qi/RxIyISHl2RTwbIducgsW9SV85tM3xrliEPjgc+
qE655Kzp+HCfMJEhcvyft3cIvM1Crxix3ndazPPK+lHIItySQibCPVNaEwARAQAB
tAdCaXRDaGFuiQJUBBMBCgA+FiEE6QszxMDnOvU38sLpsU3yBBDlpbwFAl+fVyMC
GwMFCQPCZwAFCwkIBwIGFQoJCAsCBBYCAwECHgECF4AACgkQsU3yBBDlpbyMhQ//
ejH9mjrvILh6lQe5Zpt9r5xQ8UOgta3lXtcYbsee91BO94O8pd6NrmC2H7sBGqlz
xN08E2O4R6QNI8j1Vh3fG5Ovi1ZHrXvSodOxMvpUTdc7N/Gt1kWO67HmHgLxiKIJ
QSAf3BgxHiawVpAEmk7s8Yw7RtGFnvsC3mTpP5EeIi/qaD4W+bxCpxrHyfAvUUw0
xgm4xMTQXkQiE7jLsoUxweRkPDahxcI0bJcQht4NAJS3FbFj0nAglitOipqkIXDa
xO1kSsZ9Adj/OJ5IBITTbw3xP2CJbXeIUzDegjW6rK1pJvPTC+83rM9HbsPD2dZu
JBOMyNwomIzt8QpTHRmFvM/U5LJ40S+VtacGRDvRDKW4Yb8V6cnITaTS3QUVTpyR
LvmN+eWg8VGNVFezn85gNFvNMl1VvlQ5se0wVZt16dxYbXY945QO8b3m4xvBkeqf
LwfQRq/Kz7OybhY/D717QRhPAj2HNqShlSfPpj8oT8kvnmgeoc7gEPoGk4Kb0elN
y9Dq96r005EFYVpEU4QTemm1E+tBZYzGMdCOrrbUS0z84xArtTIouLYvj4LCFmSc
xYHsYctWCjPPUM53ERIsAuGgJFSeZHbN6oWrSmZHvmVkvz5++kLH5fsGUkPuXc5j
rANOBNlZwvlMzapVJEFh7QPKiwxzn2EZZtyebFC6eWW5Ag0EX59XIwEQAJmwRplw
lZyOw3SnxMOmQj5G31uphmDClO8vHznV3i45e2ujkYulL1AamEZ1UU+uE9qpnw34
ZEPVNKvMFMMleN5VUQ1n1cGvZEIoWtXO3uftkdXu0RDynuOc/ab1JqLnbSZOd121
g6M9aQfHXSFlPQJ/gPWKR9MUtQbmFPauuLRs24iqT6O3hmyrn12MX1JccRR4JNOE
59NjvXjT+VFLw0C7QLJgFByysFOgV0v30EQWsbv5NW+JmZQgqwyCSJ/eDDcRkiXH
6SxavFHau4P+dj+B2pNIa55XDuBv0cYdDvfB8/vBlWqGjp/eKnATkg3iyaZKwsDY
Om4Zvw7ThgxPLmJhtHE+4rnIYEHMpGkWka6mX9qebUrSprVmj7752L73moZDxCZS
mMIV3SvBFECPk81QJnBNOY79Zj4apXoEGNO+4JcnK3smDVN6+vl88KFFxKvagbDo
WNuV/I7K+ACx2HwAdxwlYCj2SMsmXxIwwXqO+nu/9NvKM0aOHYOr0y3a6JWtuBl6
W3EtzMRGZ1B4KkxjUPMOrAtoYuTxxrFANBVv6TN+oMhj7rDF2SGvohThjJ7Ec7bK
3Zv0FBxdXJbm63jvmwooX78KrGa/+yrqpWYhunGWS6QjBoJzK3JCAFwBTktF26FC
/DeWs8uomsR3BwmTM7I6jCxI/hXP+stfbFFTABEBAAGJAjwEGAEKACYWIQTpCzPE
wOc69TfywumxTfIEEOWlvAUCX59XIwIbDAUJA8JnAAAKCRCxTfIEEOWlvEcZD/9C
rjcJpXxpq8TFRONlu/3cofjO3GvRkm87ylPAULkyTRdqOxJd6mLgavYtAB9VX3Cb
zz0YSLQXKRohZrzdElNgJS/Cj32QRKI8/A9K16zO3kRfPcYwfQG2m+JJo9IhDh4S
3R2f1tyrDLWyhm5HR/nEknn6MndYx6MgovthkJm7eEEF8mic/+N+ToZ/LwcbDaIG
5dW2isIRAEjAVjXKzxmQf7TU7xSkCp6V+YnQMfo9ytf32PWSJaY2Lsowt1tShINN
KiSIVzPCXY3zlkjOT6wC4DN205eeRriiYynR3MJvcplj4618o7qiV09WoiwaHa3C
ZcnqNzSL38jGM5Lv40M2FG+ILtWxuNXG0avP26BTiQUx57eNIo897V+FgeMvYSTE
sSYvJh6wtRrNdGXGNScgFyGcs6Oh+ujDZaEdClSTjFz+3+H7D1QsoaaL4UeMETiz
fHlQEDnvR30SC+ESFQm7UAFcaHuRmYoXQZ2EAFmazmRHyVObjHo334yIPz0It4dO
/2LBP1HtXjAeb4DXVbKTbxF+o2erdwaO1pybOhz3QqjIgH5MepmiOxk8e4esPcrl
l+iRV/D62p1iC5RrUSQ2oNsQNLAr/7FQJdfFW0BCUhi9Uv4cpWEM9mnHKvFD1vwW
rQTVBcv/dN0uG0ALkMa0AVHtWU8ugnXidRPUhG8a5A==
=dZAw
-----END PGP PUBLIC KEY BLOCK-----
```