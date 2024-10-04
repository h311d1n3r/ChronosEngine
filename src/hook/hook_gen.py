## @file hook_gen.py
# @brief LD_PRELOAD hook file generation engine, based on template file

import argparse
import os
import sys

from template_manager import TemplateParams, TemplateManager

TEMPLATE_PATH = '../res/chronos_hook.c.tpl'
DEFAULT_OUT_PATH = './chronos_hook.c'

def main():
    parser = argparse.ArgumentParser(description='LD_PRELOAD hook file generation engine for Chronos project.')
    parser.add_argument('dump_file', type=str, help='Output dump file path')
    parser.add_argument('target_name', type=str, help='Target function name')
    parser.add_argument('target_params_count', type=int, help='Target function parameters count')
    parser.add_argument('-output_file', type=str, help='LD_PRELOAD hook file path', required=False)

    args = parser.parse_args()
    output_path = args.output_file
    if output_path is None:
        output_path = DEFAULT_OUT_PATH
    if os.path.exists(output_path):
        overwrite_answer = input(f'Output file \"{output_path}\" already exists. Overwrite it (y/N): ')
        if overwrite_answer is None or len(overwrite_answer) == 0 or overwrite_answer.lower() != 'y':
            print('Exiting...')
            sys.exit(0)

    tpl_manager = TemplateManager(TEMPLATE_PATH)
    print('Processing template...')
    params = TemplateParams(args.dump_file, args.target_name, args.target_params_count)
    tpl_manager.process_params(params)
    tpl_manager.write_to_file(output_path)
    print(f'Done! Hook file is located at \"{output_path}\"')

if __name__ == '__main__':
    main()