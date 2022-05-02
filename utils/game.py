import base64
import hashlib
import json
import logging
import time

import gnupg
from sqlalchemy import and_

import config
from bitchan_client import DaemonCom
from database.models import Chan
from database.models import Games
from database.models import Messages
from database.models import Threads
from database.utils import session_scope
from utils.files import LF
from utils.files import human_readable_size
from utils.gateway import api
from utils.tic_tac_toe import TicTacToe

logger = logging.getLogger('bitchan.game')

DB_PATH = 'sqlite:///' + config.DATABASE_BITCHAN
daemon_com = DaemonCom()


def update_game(message_id, dict_msg, game_termination_password=None, game_player_move=None):
    errors = []
    successes = []
    msg_body = ""
    msg_extra = ""
    moves_updated = False
    game_termination_pw_hash = None

    with session_scope(DB_PATH) as new_session:
        msg = new_session.query(Messages).filter(
            Messages.message_id == message_id).first()
        if not msg:
            logger.error("{}: Game: msg not found".format(
                message_id[-config.ID_LENGTH:].upper()))
            return

        if not msg.thread:
            logger.error("{}: Game: thread not found".format(
                message_id[-config.ID_LENGTH:].upper()))
            return

        game = new_session.query(Games).filter(and_(
            Games.is_host.is_(True),
            Games.game_over.is_(False),
            Games.thread_hash == msg.thread.thread_hash)).first()

        if not game:
            logger.error("{}: Game: hosting table entry not found for thread (not host)".format(
                message_id[-config.ID_LENGTH:].upper()))

            # Set game state to that of host game
            if "game_over" in dict_msg and dict_msg["game_over"] is not None:
                test_game = new_session.query(Games).filter(and_(
                    Games.is_host.is_(False),
                    Games.game_over.is_(False),
                    Games.thread_hash == msg.thread.thread_hash)).first()
                if test_game:
                    logger.error("{}: Game: setting game_over to {}...".format(
                        message_id[-config.ID_LENGTH:].upper(), bool(dict_msg["game_over"])))
                    test_game.game_over = dict_msg["game_over"]
                    new_session.commit()
                else:
                    logger.error("{}: Game: Can't set game_over to {}, game table entry not found.".format(
                        message_id[-config.ID_LENGTH:].upper(), bool(dict_msg["game_over"])))
            return

        if game_termination_password:
            game_termination_pw_hash = hashlib.sha512(
                game_termination_password.encode('utf-8')).hexdigest()

        if (game and
                game_termination_password and
                game_termination_pw_hash and
                game_termination_pw_hash == game.game_termination_pw_hash and
                (game_player_move and game_player_move.lower() == "terminate")):
            logger.info("Game termination password provided and is valid. Ending game.")
            game.game_over = True
            msg_body += '== Game Host ==\nGame Terminated with Password\n==============='

        if game.game_initiated == "game_closed":
            logger.info("{}: Game closed".format(
                message_id[-config.ID_LENGTH:].upper()))
            return

        if game.game_initiated in [None, "uninitiated"]:
            logger.info("{}: Game awaiting initiation".format(
                message_id[-config.ID_LENGTH:].upper()))
            return

        if game.game_type not in config.GAMES:
            logger.error("{}: Game: Unknown game: {}".format(
                message_id[-config.ID_LENGTH:].upper(), game.game_type))
            return

        logger.info("{}: Game: Player Turn: {}, Command: {}".format(
            message_id[-config.ID_LENGTH:].upper(),
            game.turn_player,
            msg.game_player_move))

        if msg.game_player_move is None:
            logger.info("{}: Game: No command. Skipping processing.".format(
                message_id[-config.ID_LENGTH:].upper()))

        try:
            players = json.loads(game.players)
        except:
            players = {}

        try:
            moves = json.loads(game.moves)
        except:
            moves = {
                "game_log": [],
                "game_moves": []
            }

        if not game.game_over:
            logger.info("Game not over")
            if not game.turn_player and msg.game_player_move and msg.game_player_move.lower() == "join":
                if not msg.game_password_b_hash:
                    errors.append("Must supply a Game New Password when sending a Game Command")
                else:
                    # Player joining game
                    if "player_a" in players and "password_b_hash" not in players["player_a"]:
                        # Player A needs to be set
                        logger.info("{}: Game: Player A joined the game".format(
                            message_id[-config.ID_LENGTH:].upper()))
                        game.game_initiated = "player_a_chosen"
                        players["player_a"]["password_b_hash"] = msg.game_password_b_hash
                    elif "player_b" in players and "password_b_hash" not in players["player_b"]:
                        # Player A needs to be set
                        logger.info("{}: Game: Player B joined the game".format(
                            message_id[-config.ID_LENGTH:].upper()))
                        game.game_initiated = "player_b_chosen"
                        players["player_b"]["password_b_hash"] = msg.game_password_b_hash
                    game.players = json.dumps(players)
                    new_session.commit()
                    return
            elif (not game.turn_player and
                    ((msg.game_player_move and msg.game_player_move.lower() != "join") or
                     not msg.game_player_move)):
                logger.error("Invalid Game Command. The only current valid command is 'join'")
                return

            logger.info("{}: Players: {}".format(
                message_id[-config.ID_LENGTH:].upper(), players))
            logger.info("{}: From: {}".format(
                message_id[-config.ID_LENGTH:].upper(), msg.address_from))

            player = "A" if game.turn_player == "player_a" else "B"

            valid_mover = False
            if game.turn_player in ["player_a", "player_b"]:
                if not msg.game_player_move:
                    logger.error("Must supply a Game Command to play the game")
                    return

                # Check password hash
                logger.info("{0}: Player {1}'s turn, Player {1} sent command".format(
                    message_id[-config.ID_LENGTH:].upper(), player))
                if not msg.game_password_a:
                    logger.error("{}: Player {} didn't supply Password A (previous). Try again.".format(
                        message_id[-config.ID_LENGTH:].upper(), player))
                if not msg.game_password_b_hash:
                    logger.error("{}: Player {} didn't supply Password B (new). Try again.".format(
                        message_id[-config.ID_LENGTH:].upper(), player))
                if (game.turn_player in players and
                        "password_b_hash" in players[game.turn_player] and
                        msg.game_password_a and
                        msg.game_password_b_hash):
                    logger.info("{}: Player {} password B hash: {}".format(
                        message_id[-config.ID_LENGTH:].upper(),
                        player, players[game.turn_player]["password_b_hash"]))
                    logger.info("{}: Player {} Password A (previous): {}".format(
                        message_id[-config.ID_LENGTH:].upper(), player, msg.game_password_a))
                    password_a_hash = hashlib.sha512(
                        msg.game_password_a.encode('utf-8')).hexdigest()
                    logger.info("{}: Player {} Password A (previous) hash: {}".format(
                        message_id[-config.ID_LENGTH:].upper(), player, password_a_hash))

                    if players[game.turn_player]["password_b_hash"] == password_a_hash:
                        logger.info("{}: Player {} Password hashes match".format(
                            message_id[-config.ID_LENGTH:].upper(), player))
                        if msg.game_password_b_hash:
                            logger.info("{}: Setting Player {}'s Password B (new) Hash".format(
                                message_id[-config.ID_LENGTH:].upper(), player))
                            successes.append("Player {} Authenticated (valid Previous Password)".format(player))
                            successes.append("New Password set for Player {}".format(player))
                            players[game.turn_player]["password_b_hash"] = msg.game_password_b_hash
                            game.players = json.dumps(players)
                            valid_mover = True
                    else:
                        errors.append("Incorrect Previous Password for Player {}. Try again.".format(player))
                else:
                    errors.append("Missing Player {}'s New Password".format(player))
            else:
                errors.append("Couldn't determine the current player turn")

            #
            # Tic Tac Toe
            #
            if game.game_type == "tic_tac_toe":
                old_board_state = None

                if not errors:
                    valid_move = False
                    try:
                        move_new = int(msg.game_player_move)
                        if 1 <= move_new <= 9:
                            valid_move = True
                    except:
                        errors.append("Move does not represent an integer: {}".format(
                            msg.game_player_move))

                    ttt_o = TicTacToe()
                    ttt_o.create_board()
                    old_winner, old_board_state = ttt_o.run_game(moves["game_log"])

                    if "game_log" not in moves:
                        errors.append('"game_log" not in moves dict'.format(
                            message_id[-config.ID_LENGTH:].upper()))

                    if "game_moves" not in moves:
                        errors.append('"game_moves" not in moves dict'.format(
                            message_id[-config.ID_LENGTH:].upper()))

                    if not valid_move:
                        errors.append("Invalid move: {}. Must be 1 - 9. Try again.".format(msg.game_player_move))
                    elif move_new in moves["game_moves"]:
                        errors.append("Cannot move to a position that has already been selected".format(
                            message_id[-config.ID_LENGTH:].upper()))

                    if not errors and valid_mover and valid_move:
                        successes.append("Valid move submitted")
                        moves_updated = True
                        moves["game_moves"].append(move_new)
                        moves["game_log"].append((player, players[game.turn_player]["name"], move_new))
                        logger.info("{}: Move is valid ({}). Adding to list: {}".format(
                            message_id[-config.ID_LENGTH:].upper(), move_new, moves["game_log"]))
                        msg_extra += "History\n"
                        for i, (play, name, move) in enumerate(moves["game_log"], 1):
                            msg_extra += "{}. {} ({}): {}\n".format(i, play, name, move)
                        msg_extra += "\n"

                if successes:
                    msg_extra += "Success:\n{}\n".format("\n".join(successes))
                if errors:
                    msg_body += "Error:\n{}\n\n".format("\n".join(errors))
                else:
                    ttt = TicTacToe()
                    ttt.create_board()
                    winner, board_state = ttt.run_game(moves["game_log"])

                    if old_board_state and old_board_state != board_state:
                        msg_body += "Board Updated\n"
                    else:
                        msg_body += "Board Not Updated\n"

                    msg_body += "\n Board Moves" \
                                "\n-------------" \
                                "\n| 1 | 2 | 3 |" \
                                "\n| 4 | 5 | 6 |" \
                                "\n| 7 | 8 | 9 |" \
                                "\n-------------\n\n"

                    msg_body += "Current Board\n{}\n".format(board_state)

                    if not errors:
                        # No errors, change player turn and show new board
                        if moves_updated and winner != -1:
                            msg_body += "\nThe game has ended.\n"
                            if winner:
                                msg_body += "\n{} Wins!".format(winner)
                                game.game_over = True
                                new_session.commit()
                            elif winner is None:
                                msg_body += "\nNo one wins."
                                game.game_over = True
                                new_session.commit()
                        else:
                            # Change to the other player's turn
                            if game.turn_player == "player_a":
                                game.turn_player = "player_b"
                            else:
                                game.turn_player = "player_a"

            #
            # Chess
            #
            elif game.game_type == "chess":
                old_board_state = None

                if not errors:
                    import chess

                    chess_board = chess.Board()
                    for move in moves["game_moves"]:
                        chess_board.push_san(move)
                    old_board_state = str(chess_board)

                    try:
                        position = msg.game_player_move.lower()
                        move_new = str(chess_board.parse_san(position))
                        valid_move = chess.Move.from_uci(move_new) in chess_board.legal_moves
                    except:
                        valid_move = False

                    board_state = old_board_state

                    if "game_moves" not in moves:
                        errors.append('"game_moves" not in moves dict'.format(
                            message_id[-config.ID_LENGTH:].upper()))
                    elif not valid_move:
                        errors.append("Invalid move: {}. Try again.".format(msg.game_player_move))
                    elif valid_mover:
                        successes.append("Valid move submitted")
                        chess_board.push_san(move_new)
                        board_state = str(chess_board)
                        moves_updated = True
                        moves["game_moves"].append(move_new)
                        moves["game_log"].append((player, players[game.turn_player]["name"], move_new))
                        logger.info("{}: Move is valid ({}). Adding to list: {}".format(
                            message_id[-config.ID_LENGTH:].upper(), move_new, moves["game_log"]))
                        msg_extra += "History\n"
                        for i, (play, name, move) in enumerate(moves["game_log"], 1):
                            msg_extra += "{}. {} ({}): {}\n".format(i, play, name, move)
                    else:
                        logger.error('Invalid command: "{}"'.format(msg.game_player_move))

                if successes:
                    msg_extra += "\nSuccess:\n{}\n".format("\n".join(successes))
                if errors:
                    msg_body += "\nError:\n{}\n".format("\n".join(errors))
                else:
                    # No errors, change player turn and show new board
                    if old_board_state and old_board_state != board_state:
                        msg_extra += "\nBoard Updated\n"
                    else:
                        msg_body += "\nBoard Not Updated\n"

                    if moves_updated:
                        checkmate = chess_board.is_checkmate()
                        stalemate = chess_board.is_stalemate()

                        if checkmate:
                            msg_body += "\nThe game has ended with a checkmate.\n"
                            msg_body += "\nPlayer {} ({}, {}) Wins!".format(
                                player, players[game.turn_player]["name"], players[game.turn_player]["address"])
                            game.game_over = True
                            new_session.commit()
                        elif stalemate:
                            msg_body += "\nThe game has ended with a stalemate."
                            game.game_over = True
                            new_session.commit()
                        else:
                            if game.turn_player == "player_a":
                                game.turn_player = "player_b"
                            else:
                                game.turn_player = "player_a"

                msg_extra += "\nCurrent Board\n{}\n".format(board_state)

        if not errors:
            if not game.game_over:
                # Show player turn
                msg_body += "\nTurn: Player "

                if game.turn_player == "player_a":
                    msg_body += "A"
                else:
                    msg_body += "B"

                player_address = players[game.turn_player]["address"]
                if not player_address:
                    player_address = "Anonymous"

                if "name" in players[game.turn_player] and players[game.turn_player]["name"]:
                    msg_body += " ({}, {})".format(
                        players[game.turn_player]["name"],
                        player_address)

            if moves_updated:
                # Add position to move list
                moves_json = json.dumps(moves)
                if moves_json != game.moves:
                    game.moves = moves_json
                new_session.commit()

        if errors:
            for each_error in errors:
                logger.error(each_error)

        dict_message = {
            "version": config.VERSION_MSG,
            "timestamp_utc": time.time(),
            "message_type": "game",
            "game": game.game_type,
            "game_hash": game.game_hash,
            "game_over": game.game_over,
            "game_moves": moves["game_moves"],
            "game_termination_pw_hash": game.game_termination_pw_hash,
            "thread_hash": msg.thread.thread_hash,
            "message": msg_body,
            "message_extra": msg_extra
        }

        thread = new_session.query(Threads).filter(
            Threads.thread_hash == game.thread_hash).first()
        if not thread:
            logger.error("{}: Game {}: Thread not found".format(
                message_id[-config.ID_LENGTH:].upper(), game.game_hash))
            return

        pgp_passphrase_msg = config.PGP_PASSPHRASE_MSG
        chan = new_session.query(Chan).filter(
            Chan.address == thread.chan.address).first()
        if chan and chan.pgp_passphrase_msg:
            pgp_passphrase_msg = chan.pgp_passphrase_msg

        gpg = gnupg.GPG()
        message_encrypted = gpg.encrypt(
            json.dumps(dict_message),
            symmetric="AES256",
            passphrase=pgp_passphrase_msg,
            recipients=None)

        message_send = base64.b64encode(message_encrypted.data).decode()

        logger.info("{}: Game message size: {}".format(
            message_id[-config.ID_LENGTH:].upper(), len(message_send)))

        # prolong inventory clear if sending a message
        now = time.time()
        if daemon_com.get_timer_clear_inventory() > now:
            daemon_com.update_timer_clear_inventory(config.CLEAR_INVENTORY_WAIT)

        # Don't allow a message to send while Bitmessage is restarting
        allow_send = False
        timer = time.time()
        while not allow_send:
            if daemon_com.bitmessage_restarting() is False:
                allow_send = True
            if time.time() - timer > config.BM_WAIT_DELAY:
                logger.error(
                    "Unable to send game message: "
                    "Could not detect Bitmessage running.")
                return
            time.sleep(1)

        lf = LF()
        if lf.lock_acquire(config.LOCKFILE_API, to=config.API_LOCK_TIMEOUT):
            return_str = None
            try:
                return_str = api.sendMessage(
                    thread.chan.address,
                    game.host_from_address,
                    "",
                    message_send,
                    2,
                    60 * 60 * 24 * 28)
                if return_str:
                    logger.info("{}: Daemon game message sent from {} to {}: {}".format(
                        message_id[-config.ID_LENGTH:].upper(),
                        game.host_from_address, thread.thread_hash_short, return_str))
            except Exception:
                logger.exception("update_game()")
            finally:
                time.sleep(config.API_PAUSE)
                lf.lock_release(config.LOCKFILE_API)
                return_msg = "{}: Game post of size {} placed in send queue. The time it " \
                             "takes to send a message is related to the size of the " \
                             "post due to the proof of work required to send. " \
                             "Generally, the larger the post, the longer it takes to " \
                             "send. Posts ~10 KB take around a minute or less to send, " \
                             "whereas messages >= 100 KB can take several minutes to " \
                             "send. BM returned: {}".format(
                    message_id[-config.ID_LENGTH:].upper(),
                    human_readable_size(len(message_send)), return_str)


def initialize_game(game_id):
    moves = None

    with session_scope(DB_PATH) as new_session:
        game = new_session.query(Games).filter(and_(
            Games.id == game_id),
            Games.game_over.is_(False)).first()
        if game:
            if not game.is_host:
                logger.info("Game {}: Not host, not sending game posts.".format(game.game_hash))
                return

            players = json.loads(game.players)
            player_a_name = players["player_a"]["name"]
            if not player_a_name:
                player_a_name = "A"
            player_b_name = players["player_b"]["name"]
            if not player_b_name:
                player_b_name = "B"

            player_a_address = players["player_a"]["address"]
            if not player_a_address:
                player_a_address = "Anonymous"
            player_b_address = players["player_b"]["address"]
            if not player_b_address:
                player_b_address = "Anonymous"

            body = "A game is starting. The host is {}".format(game.host_from_address)
            body += "\nGame: {}".format(config.GAMES[game.game_type])
            body += "\nRules: None\n"

            if game.game_initiated == "uninitiated":
                if game.game_termination_pw_hash:
                    body += '\nThe host has provided a password that can terminate the game at any time. To terminate the game, enter the password in the Game Termination Password field, enter "terminate" (without quotes) in the Game Command field, then Post.\n'.format(
                        game.host_from_address)
                else:
                    body += "\nThe host has not provided a password to terminate the game and it can only end when when there is a winner or stalemate.\n".format(
                        game.host_from_address)

            #
            # Tic Tac Toe
            #
            if game.game_type == "tic_tac_toe":
                ttt = TicTacToe()
                ttt.create_board()
                winner, board_state = ttt.run_game([])

            #
            # Chess
            #
            elif game.game_type == "chess":
                import chess
                board_state = chess.Board()

            if game.game_initiated == "uninitiated":
                game.game_initiated = "waiting_player_a"
                body += '\nThis is a 2 player game and 0 players have joined.' \
                        '\nTo join the game, enter a password in the Game New Password field, enter "join" (without quotes) in the Game Command field, then Post.' \
                        '\n\nNote: Do not lose the Game New Password, otherwise you will be unable to continue playing.'

            if game.game_initiated == "player_a_chosen":
                game.game_initiated = "waiting_player_b"
                body += '\nPlayer A has joined the game. Waiting for a Player B to join the game.' \
                        '\nTo join the game, enter a password in the Game New Password field, enter "join" (without quotes) in the Game Command field, then Post.' \
                        '\n\nNote: Do not lose Game New Password, otherwise you will be unable to continue playing.'

            if game.game_initiated == "player_b_chosen":
                game.game_initiated = "game_open"
                game.turn_player = "player_a"

                #
                # Tic Tac Toe
                #
                if game.game_type == "tic_tac_toe":
                    moves = []
                    body += """\nPlayer B has joined the game. Both players have joined and the game has started.
When it's your turn to make a move, enter the password that was previously entered in the New Password field in the Previous Password field, enter a new password in the Game New Password field, enter your move in the Game Command field, then Post.

Note: Do not lose the New Password, otherwise you will be unable to continue playing.

Tic Tac Toe Board
-------------
| 1 | 2 | 3 |
| 4 | 5 | 6 |
| 7 | 8 | 9 |
-------------

To select a place on the board, use a single numeric character, 1 - 9, which hasn't already been chosen, as your Game Command.

Current Board
{b}

Player A is {pa} ({paa})
Player B is {pb} ({pba})

Current turn: Player A ({pa}, {paa})""".format(
                        host=game.host_from_address,
                        b=board_state,
                        pa=player_a_name,
                        pb=player_b_name,
                        paa=player_a_address,
                        pba=player_b_address)

                #
                # Chess
                #
                elif game.game_type == "chess":
                    moves = []
                    body += """\nPlayer B has joined the game. Both players have joined and the game is starting. When it's your turn to make a move, enter the password that was previously entered in the New Password field in the Previous Password field, enter a new password in the New Password field, and your move in the Game Command field.

Note: Do not lose the password you enter in New Password, otherwise you will be unable to continue playing.

Chess Board
  a b c d e f g h
8 r n b q k b n r
7 p p p p p p p p
6 . . . . . . . .
5 . . . . . . . .
4 . . . . . . . .
3 . . . . . . . .
2 P P P P P P P P
1 R N B Q K B N R

Standard game commands (e.g. e4) can be used as well as [from][to] positions (e.g. e2e4).

Current Board
{b}

Player A is {pa} ({paa})
Player B is {pb} ({pba})

Current turn: Player A ({pa}, {paa})""".format(
                        host=game.host_from_address,
                        b=board_state,
                        pa=player_a_name,
                        pb=player_b_name,
                        paa=player_a_address,
                        pba=player_b_address)

            thread = new_session.query(Threads).filter(
                Threads.thread_hash == game.thread_hash).first()
            if not thread:
                logger.error("Game {}: Thread not found".format(game.game_hash))
                return

            dict_message = {
                "version": config.VERSION_MSG,
                "timestamp_utc": time.time(),
                "message_type": "game",
                "game": game.game_type,
                "game_over": False,
                "game_hash": game.game_hash,
                "game_moves": moves,
                "game_termination_pw_hash": game.game_termination_pw_hash,
                "thread_hash": game.thread_hash,
                "message": body,
                "message_extra": None
            }

            pgp_passphrase_msg = config.PGP_PASSPHRASE_MSG
            chan = new_session.query(Chan).filter(
                Chan.address == thread.chan.address).first()
            if chan and chan.pgp_passphrase_msg:
                pgp_passphrase_msg = chan.pgp_passphrase_msg

            gpg = gnupg.GPG()
            message_encrypted = gpg.encrypt(
                json.dumps(dict_message),
                symmetric="AES256",
                passphrase=pgp_passphrase_msg,
                recipients=None)

            message_send = base64.b64encode(message_encrypted.data).decode()

            # prolong inventory clear if sending a message
            now = time.time()
            if daemon_com.get_timer_clear_inventory() > now:
                daemon_com.update_timer_clear_inventory(config.CLEAR_INVENTORY_WAIT)

            # Don't allow a message to send while Bitmessage is restarting
            allow_send = False
            timer = time.time()
            while not allow_send:
                if daemon_com.bitmessage_restarting() is False:
                    allow_send = True
                if time.time() - timer > config.BM_WAIT_DELAY:
                    logger.error(
                        "Unable to send game message: "
                        "Could not detect Bitmessage running.")
                    return
                time.sleep(1)

            lf = LF()
            if lf.lock_acquire(config.LOCKFILE_API, to=config.API_LOCK_TIMEOUT):
                return_str = None
                try:
                    return_str = api.sendMessage(
                        thread.chan.address,
                        game.host_from_address,
                        "",
                        message_send,
                        2,
                        60 * 60 * 24 * 28)
                    if return_str:
                        logger.info("Daemon game message sent from {} to {}: {}".format(
                            game.host_from_address, thread.thread_hash_short, return_str))
                        new_session.commit()
                except Exception:
                    logger.exception("initialize_game()")
                finally:
                    time.sleep(config.API_PAUSE)
                    lf.lock_release(config.LOCKFILE_API)
                    return_msg = "Game post of size {} placed in send queue. The time it " \
                                 "takes to send a message is related to the size of the " \
                                 "post due to the proof of work required to send. " \
                                 "Generally, the larger the post, the longer it takes to " \
                                 "send. Posts ~10 KB take around a minute or less to send, " \
                                 "whereas messages >= 100 KB can take several minutes to " \
                                 "send. BM returned: {}".format(
                        human_readable_size(len(message_send)), return_str)
