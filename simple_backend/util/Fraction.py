# -*- coding: utf-8 -*-
import fractions

__author__ = 'mys'


class Fraction(fractions.Fraction):
    def __composite_values__(self):
        return self.numerator, self.denominator

    def get_integer_and_fractional_part(self, prec):
        return self.__integer_fractional_part(self.numerator, self.denominator, prec)

    @staticmethod
    def __integer_fractional_part(numerator, denominator, prec):
        """
        Find the integer part and an approximated fractional part of a Fraction, using long division

        Example: -99/8 is approximated to -12.38 if the precision is 2, -12.375 if the precision is 3 (the exact value),
                 -12.3750 if the precision is 4 and so forth.
                 The first example returns the tuple: (u'-12', u'38')

        :param numerator: The numerator
        :param denominator: The denominator
        :param prec: Precision of fractional part

        :type numerator long
        :type denominator long
        :type prec long

        :return: The integer and fractional part, where the fractional part are of length 'prec'
        :rtype unicode, unicode
        """
        # Save the sign for later use
        sign = ''
        if numerator < 0:
            sign = '-'
            numerator *= -1
        # Find the integer part
        integer = numerator // denominator
        # Save the rest
        numerator -= denominator * integer
        # Use long division to find the result
        res = u''
        it = prec
        while numerator > 0 and it >= 0:
            res += unicode(numerator // denominator)
            numerator = numerator % denominator * 10
            it -= 1
        # Convert to unicode
        integer = unicode(integer)
        # res always start with 0 (the integer part)
        fraction = res[1:]
        if numerator != 0 and numerator // denominator >= 5:
            # Check if it did not divide and the next causes to rounding up
            res = unicode(long(''.join((integer, fraction))) + 1).ljust(prec, '0')
            return sign + res[:-prec], res[-prec:]
        else:
            # Return the integer part and the fraction part with the wanted precision
            return sign + integer, fraction.ljust(prec, '0')
