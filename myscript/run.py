import os
import sys
import yaml
from argparse import ArgumentParser, ArgumentTypeError
from pathlib import Path
import subprocess

def validPath(path: str) -> Path :
    try:
        abspath = Path(path)
    except Exception as e:
        raise ArgumentTypeError(f'Invalid input path: {path}') from e
    if not abspath.exists():
        raise ArgumentTypeError(f'{abspath} not exist')
    return abspath.resolve()
class Executor :
    def __init__(self, args, config) -> None :
        self.cur_input = args.input
        self.src = args.src
        self.target_line = args.line
        self.out_dir = config.out_dir
        self.config = config
        
    def __get_symcc_cmd(self) : 
        cmd = []
        concolic_env = {'SYMCC_ENABLE_LINEARIZATION': '1', 
                        # 'SYMCC_AFL_COVERAGE_MAP': str(self.bitmap),
                        'SYMCC_INPUT_FILE': str(self.cur_input),
                        'SYMCC_OUTPUT_DIR' : str(self.out_dir),
                        'SYMCC_DIRECTED' : '1',  
                        'SYMCC_NEGATE_TARGET_FILE' : str(self.src),
                        'SYMCC_NEGATE_TARGET_LINE' : str(self.target_line)
                        }
        cmd.append(self.config.symcc)

        return {"cmd":cmd,"env":concolic_env}
    def solve(self) -> None :
        cmd, env = self.__get_symcc_cmd()
        print(cmd)

        stdout, stderr = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env).communicate()
        print(stdout.decode('utf-8'))
        print(stderr.decode('utf-8'))
        pass

def main() :
    
    parser = ArgumentParser(description='Symbolic Utility')
    parser.add_argument('-c', dest='config', required=True, type=validPath,help='Path of the configure yaml file')
    parser.add_argument('-l', dest='line', required=True, type=int, help='Target line numbers, format \"1,2,3,4\" ')
    parser.add_argument('-s', dest='src', required=True, type=validPath, help='Target source code file path')
    parser.add_argument('-i', dest='input', required=True, type=validPath, help='Input file path')
    args = parser.parse_args()
    config = yaml.load(args.config)

    config.out_dir = Path(config.out_dir).resolve()

    executor = Executor(args, config)
    executor.solve()

if __name__ == '__main__' :
    sys.exit(main())