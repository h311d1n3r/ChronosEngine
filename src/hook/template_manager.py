from typing import Dict

class TemplateParams:
    dump_file: str = ''
    target_name: str = ''
    target_params_count: int = 0

    def __init__(self, dump_file, target_name, target_params_count):
        self.dump_file = dump_file
        self.target_name = target_name
        self.target_params_count = target_params_count

class TemplateManager:

    _template_data: bytearray = None

    def __init__(self, template_path: str) -> None:
        with open(template_path, 'rb') as template_f:
            self._template_data = template_f.read()
    
    def _chronos_template_var(self, var_name: str) -> str:
        return f'%CHRONOS_{var_name.upper()}%'

    def process_params(self, params: TemplateParams) -> None:
        replace_list: Dict[str, str] = {
            'target_name': params.target_name,
            'target_signature_params': ', '.join([f'uint64_t param{i}' for i in range(params.target_params_count)]),
            'target_notype_params': ', '.join([f'param{i}' for i in range(params.target_params_count)]),
            'target_params_count': str(params.target_params_count),
            'dump_file': params.dump_file
        }

        for var_name in replace_list:
            var_value: str = replace_list[var_name]
            var_name: str = self._chronos_template_var(var_name)
            self._template_data = self._template_data.replace(var_name.encode(), var_value.encode())

    def write_to_file(self, out_path: str):
        out_f = open(out_path, 'wb')
        out_f.write(self._template_data)
        out_f.close()