#!/usr/bin/env python

# Copyright (c) 2015 Eric Entzel

# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
import logging

END = -1

# HTML5 void-elements that do not require a closing tag
# https://html.spec.whatwg.org/multipage/syntax.html#void-elements
VOID_ELEMENTS = ('area', 'base', 'br', 'col', 'embed', 'hr', 'img', 'input',
                 'link', 'meta', 'param', 'source', 'track', 'wbr')

logger = logging.getLogger("bitchan.html_truncate")


class UnbalancedError(Exception):
    pass


class OpenTag:
    def __init__(self, tag, rest=''):
        self.tag = tag
        self.rest = rest

    def as_string(self):
        return '<' + self.tag + self.rest + '>'


class CloseTag(OpenTag):
    def as_string(self):
        return '</' + self.tag + '>'


class SelfClosingTag(OpenTag):
    pass


class Tokenizer:
    def __init__(self, input):
        self.input = input
        self.counter = 0  # points at the next unconsumed character of the input

    def __next_char(self):
        self.counter += 1
        return self.input[self.counter]

    def next_token(self):
        try:
            char = self.input[self.counter]
            self.counter += 1
            if char == '&':
                return self.__entity()
            elif char != '<':
                return char
            elif self.input[self.counter] == '/':
                self.counter += 1
                return self.__close_tag()
            else:
                return self.__open_tag()
        except IndexError:
            return END

    def __entity(self):
        """Return a token representing an HTML character entity.
        Precondition: self.counter points at the character after the &
        Postcondition: self.counter points at the character after the ;
        """
        char = self.input[self.counter]
        entity = ['&']
        while char != ';':
            entity.append(char)
            char = self.__next_char()
        entity.append(';')
        self.counter += 1
        return ''.join(entity)

    def __open_tag(self):
        """Return an open/close tag token.
        Precondition: self.counter points at the first character of the tag name
        Postcondition: self.counter points at the character after the <tag>
        """
        char = self.input[self.counter]
        tag = []
        rest = []
        while char != '>' and char != ' ':
            tag.append(char)
            char = self.__next_char()
        while char != '>':
            rest.append(char)
            char = self.__next_char()
        if self.input[self.counter - 1] == '/':
            self.counter += 1
            return SelfClosingTag(''.join(tag), ''.join(rest))
        elif ''.join(tag) in VOID_ELEMENTS:
            self.counter += 1
            return SelfClosingTag(''.join(tag), ''.join(rest))
        else:
            self.counter += 1
            return OpenTag(''.join(tag), ''.join(rest))

    def __close_tag(self):
        """Return an open/close tag token.
        Precondition: self.counter points at the first character of the tag name
        Postcondition: self.counter points at the character after the <tag>
        """
        char = self.input[self.counter]
        tag = []
        while char != '>':
            tag.append(char)
            char = self.__next_char()
        self.counter += 1
        return CloseTag(''.join(tag))


def truncate(str, target_len, target_lines=None, ellipsis=''):
    """Returns a copy of str truncated to target_len characters,
    preserving HTML markup (which does not count towards the length).
    Any tags that would be left open by truncation will be closed at
    the end of the returned string.  Optionally append ellipsis if
    the string was truncated."""
    stack = []   # open tags are pushed on here, then popped when the matching close tag is found
    retval = []  # string to be returned
    length = 0   # number of characters (not counting markup) placed in retval so far
    lines = 0
    tokens = Tokenizer(str)
    tok = tokens.next_token()
    is_truncated = False
    while tok != END:
        if not length < target_len or (target_lines and lines >= target_lines):
            retval.append(ellipsis)
            is_truncated = True
            break
        if tok.__class__.__name__ == 'OpenTag':
            stack.append(tok)
            retval.append(tok.as_string())
        elif tok.__class__.__name__ == 'CloseTag':
            if stack[-1].tag == tok.tag:
                stack.pop()
                retval.append(tok.as_string())
            else:
                raise UnbalancedError(tok.as_string())
        elif tok.__class__.__name__ == 'SelfClosingTag':
            retval.append(tok.as_string())
            if tok.as_string() == "<br/>":
                lines += 1
        else:
            retval.append(tok)
            length += 1
        tok = tokens.next_token()
    while len(stack) > 0:
        tok = CloseTag(stack.pop().tag)
        retval.append(tok.as_string())
    return is_truncated, ''.join(retval)
