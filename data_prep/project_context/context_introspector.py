import datetime
import requests
from collections import defaultdict
import json
import os

class ContextRetriever:
    def __init__(self, project_name: str, function_name: str):
        self._project_name = project_name
        self._function_name = function_name
        #self._current_date = datetime.date.today().strftime('%Y-%m-%d').replace('-','')
        self._current_date = '20240131'
        
        introspector_base_url = f'https://storage.googleapis.com/oss-fuzz-introspector/{self._project_name}/inspector-report/{self._current_date}/'

        self._introspector_summary = introspector_base_url + 'summary.json'
        self._introspector_debug_info = introspector_base_url + 'all_debug_info.json'
        self._introspector_source_base = introspector_base_url + 'source-code'

        self._all_functions_summary = defaultdict(list)
        self._all_types = defaultdict(list)

    def _extract_tags_and_raw_type_from_arg_info(self, arg : str):
        # Types are sometimes of the form <tag>.<typename>
        raw_arg_type = arg
        tag = ''
        tokens = arg.split('.')

        if len(tokens) == 2:
            tag = tokens[0]
            raw_arg_type = tokens[1]

        return tag, raw_arg_type

    def _refine_function_list_from_summary(self):
        all_functions = self._summary_report['MergedProjectProfile']['all-functions']

        # Functions are all grouped into the same name, and multiple nodes can exist per function name (I think)
        # This is to support name-mangling in C++ where functions can be overloaded and have the same de-mangled name
        for function in all_functions:
            arg_tags = []
            raw_arg_types = []

            for arg in function['Args']:
                arg_tag, raw_arg_type = self._extract_tags_and_raw_type_from_arg_info(arg)
                arg_tags.append(arg_tag)
                raw_arg_types.append(raw_arg_type)

            return_type = function.get('return_type', '')
            return_tag, raw_return_type = self._extract_tags_and_raw_type_from_arg_info(return_type)

            self._all_functions_summary[function['Func name']].append({
                'filename':
                function['Functions filename'],
                'args':
                function['Args'],
                'arg_names':
                function.get('ArgNames', []),
                'arg_tags':
                arg_tags,
                'raw_arg_types':
                raw_arg_types,
                'return_type':
                return_type,
                'return_tag':
                return_tag,
                'raw_return_type':
                raw_return_type,
                'raw_function_name':
                function.get('raw-function-name', ''),
                'source_line_begin':
                function.get('source_line_begin', '-1'),
                'source_line_end':
                function.get('source_line_end', '-1'),
                'callsites':
                function.get('callsites', [])
                })

    def _get_all_types(self):
        for typeinfo in self._debug_report['all_types']:
            self._all_types[typeinfo['name']].append(typeinfo)


    def get_introspector_data(self):
        raw_debug_json = requests.get(self._introspector_debug_info, timeout=5)
        self._debug_report = json.loads(raw_debug_json.text)

        raw_summary_json = requests.get(self._introspector_summary, timeout=5)
        self._summary_report = json.loads(raw_summary_json.text)

        self._refine_function_list_from_summary()
        self._get_all_types()

    def get_function_signature(self) -> str:
        # Only retrieves one function signature for a particular name now
        function_signature = ''

        function_info_list = self._all_functions_summary.get(self._function_name, [])

        if function_info_list is None:
            return function_signature

        function = function_info_list[0]

        function_signature += function['raw_return_type']
        function_signature += ' '
        function_signature += self._function_name
        function_signature += '('
        for idx, arg in enumerate(function['raw_arg_types']):
            function_signature += arg
            if idx < len(function['raw_arg_types']) - 1:
                function_signature += ','
        function_signature += ')'

        return function_signature

    def _get_function_info_raw(self):
        function_info_list = self._all_functions_summary[self._function_name]
        function_info = function_info_list[0]
        return function_info

    def _desugar_type(self, typename: str) -> str:
        typename = typename.replace('*', '')
        type_tokens = typename.split(' ')
        
        if 'const' in type_tokens:
            type_tokens.remove('const')

        if 'volatile' in type_tokens:
            type_tokens.remove('volatile')

        if '' in type_tokens:
            type_tokens.remove('')

        return ' '.join(type_tokens)

    def _get_types_seen_in_function(self):
        function_info = self._get_function_info_raw()
        function_arg_types = function_info['raw_arg_types']
        function_arg_tags = function_info['arg_tags']
        function_return_type = function_info['raw_return_type']
        function_return_tag = function_info['return_tag']
        arg_names = function_info['arg_names']

        types = set()

        if function_return_tag is not None:
            types.add(self._desugar_type(function_return_type))

        # CV-dequalify and remove the pointer (desugar the type) for the argument to get the base type
        for idx, tag in enumerate(function_arg_tags):
            if tag is None:
                continue
            types.add(self._desugar_type(function_arg_types[idx]))

        return types

    def get_function_type_info(self) -> str:
        types = self._get_types_seen_in_function()
        print(types)
        for typename in types:
            print(f'Searching for type: {typename}')
            typeinfo = self._all_types.get(typename, '')

            if len(typeinfo) == 0:
                print(f'Could not retrieve type: {typename}')
                continue

            typeinfo = typeinfo[0]

            path = os.path.abspath(typeinfo['source']['source_file'])
            raw_source = requests.get(self._introspector_source_base + path, timeout=5).text
            source_lines = raw_source.split('\n')

def main():
    a = ContextRetriever('htslib', 'sam_hrecs_find_key')
    a.get_introspector_data()
    print(f'Function signature: {a.get_function_signature()}')
    a.get_function_type_info()

main()
