import logging

logger = logging.getLogger('bitchan.tic_tac_toe')

import random


class TicTacToe:
    def __init__(self):
        self.board = []

    def create_board(self):
        for i in range(3):
            row = []
            for j in range(3):
                row.append('-')
            self.board.append(row)

    @staticmethod
    def get_random_first_player():
        return random.randint(0, 1)

    def fix_spot(self, pos, player):
        if pos in [1, 2, 3]:
            row = 0
            col = pos - 1
        elif pos in [4, 5, 6]:
            row = 1
            col =  pos - 4
        elif pos in [7, 8, 9]:
            row = 2
            col = pos - 7
        else:
            logger.error("Invalid input")
            return
        self.board[row][col] = player

    def is_player_win(self, player):
        win = None

        n = len(self.board)

        # File "/home/bitchan/utils/tic_tac_toe.py", line 57, in is_player_win
        # if self.board[j][i] != player:
        # IndexError: list index out of range

        # checking rows
        for i in range(n):

            win = True
            for j in range(n):
                if self.board[i][j] != player:
                    win = False
                    break
            if win:
                return win

        # checking columns
        for i in range(n):
            win = True
            for j in range(n):
                if self.board[j][i] != player:
                    win = False
                    break
            if win:
                return win

        # checking diagonals
        win = True
        for i in range(n):
            if self.board[i][i] != player:
                win = False
                break
        if win:
            return win

        win = True
        for i in range(n):
            if self.board[i][n - 1 - i] != player:
                win = False
                break
        if win:
            return win
        return False

    def is_board_filled(self):
        for row in self.board:
            for item in row:
                if item == '-':
                    return False
        return True

    @staticmethod
    def swap_player_turn(player):
        return 'X' if player == 'O' else 'O'

    def show_board(self):
        board_str = "-------------\n"
        for r, row in enumerate(self.board):
            board_str += "|"
            for c, item in enumerate(row):
                board_str += " {} |".format(item)
                if r in [0, 1] and c == 2:
                    board_str += "\n"
        board_str += "\n-------------"
        return board_str

    def run_game(self, list_moves):
        for player, name, move in list_moves:
            self.fix_spot(move, name)

            if self.is_player_win(name):
                logging.info("Player {} wins the game!".format(name))
                winner = name
                return winner, self.show_board()

            if self.is_board_filled():
                logging.info("Match Draw!")
                winner = None
                return winner, self.show_board()

        return -1, self.show_board()

    def start(self):
        self.create_board()

        player = 'X' if self.get_random_first_player() == 1 else 'O'
        while True:
            logging.info("Player {player} turn")

            print(self.show_board())

            invalid = True
            space = None
            while invalid:
                try:
                    space = int(input("Enter position (1 - 9): "))
                    invalid = False
                except KeyboardInterrupt:
                    print("End")
                    raise
                except Exception:
                    print("Try Again")

            self.fix_spot(space, player)

            if self.is_player_win(player):
                logging.info("Player {player} wins the game!")
                break

            if self.is_board_filled():
                print("Match Draw!")
                break

            player = self.swap_player_turn(player)

        print()
        self.show_board()


if __name__ == "__main__":
    tic_tac_toe = TicTacToe()
    tic_tac_toe.start()
