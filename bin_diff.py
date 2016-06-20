from __future__ import print_function
import argparse

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='bin diff')
    parser.add_argument('file1')
    parser.add_argument('file2')
    args = vars(parser.parse_args())
    f1 = open(args['file1'], 'rb')
    f2 = open(args['file2'], 'rb')
    tups = zip(f1.read(), f2.read())
    for i, t in enumerate(tups):
        if t[0] != t[1]:
            print('Byte difference {} : {} at offset {}'
                  .format(t[0], t[1], i))

