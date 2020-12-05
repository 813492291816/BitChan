# Bugs

 - Whonix Cannot find URL for file downloads?
 - Joining a board induces an inventory wipe and resync to download messages prior to joining the board. If any admin commands were given to change access, these are processed as they are received, leading to potentially unintended behaviors such as deleting posts due to unauthorized access. Fix: detect when inventory sync has completed, then sequentially process all admin commands, then posts.
 - If attempting to post a message with a lot of text (>4096K) and the message has an error that returns it to the user, a "cookie too large" error is produced.

# Ideas

 - add ~~exporting and~~ importing to preserve address book, identities, lists, and boards
 - allow setting post TTL
 - show recently updated lists on home page
 - allow bans to be reversible
 - allow bans durations
 - move board and list links side by side (2 columns)
 - allow threads to be locked
 - allow threads to be stickied
 - show a catalog of threads from all boards, ordered by most recent post
 - show a catalog of all threads per board, ordered by most recent post
 - allow boards/lists to have categories (to group together)
 - allow changing board/list label
 - mod logs? Ex: Post deleted at time t in thread x by user y. Posts deleted without comment totally disappear, so there should be a record. Maybe with optional admin display, where the owner is able to choose between logging it as "deleted by \[admin\]" or "deleted by anonymous"
 - refresh threads for new board joiners, either automatically or manually. Posting with an identity will be required to authenticate the sender. Anyone receiving the refreshed messages who already has one will see no change, but anyone who doesn't have a message will see it appear. This is more crucial for OPs than replies. The refresh function will preserve the original timestamp. If a recipient of a refreshed post previously deleted reply, it should stay deleted (deleted post IDs are currently logged in a database until the message TTL expires).
 - when someone goes to reply by clicking a post id and has text highlighted in that post to which one is replying, that text should be copied below the message id in the body of the reply's comment box.
 - allow deletion of images on posts that prevent them from being redownloaded (locally blacklist a message ID).
 - allow ability to sort messages by sent or received time
 - add post tree view
 - add page for managing PGP keyring, public/private keys
 - add support for PGP signatures of posts or messages within posts
 - allow conversion to 12-hour time display
 - add option for auto-loop and default volume for audio/video files
 - add "a new reply to your post" desktop notifications
 - report board: Any user can report a post in an imageboard chan and it will get duplicated and sent to a report chan. The reported post can include a reason why it was reported. A board owner could create a report board and set it as a permission of a newly-created board. The owner/admin could track the status of the board without having to monitor every post in every thread of a board. This tracking, provided by the user generated reports, can allow the owner/admin to decide whether the posting rules need to be updated or if the board should be abandoned for a new one.
 - more board rules: pictures or other files could be disabled, message length
 - add post editing (non-board addresses only)
 - add 'no bump' and 'anchor' option: Allow OPs and repliers the option to NOT bump a thread. Anchoring a thread means that no post can bump a thread. This usually happens when a thread is low quality but not so low as to warrant being deleted. The owner/admin should be allowed to change the thread status to anchored. Also, regular users should be able to, in addition to hiding or deleting a thread, anchor it. In tandem with this, or if anchoring is not possible, allow users to have a list of threads that they are watching.
 - add list of watched threads
 - add "last 100" thread view. Only load the last 100 posts plus the OP appears at the top.
 - add "expand all images" button
 - add more copy-to-clipboard buttons for commonly-used text strings/IDs
 - add bell icon in top right indicating a new software version is available
 - allow owners/admins to see the from address of an item on a list, for banning/restricting purposes
 - allow owners/admins to add text under posts (post content cannot be modified but a custom message can be added below it, e.g. "USER WAS BANNED FOR THIS POST...")
