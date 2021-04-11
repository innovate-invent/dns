import resolve from '@rollup/plugin-node-resolve';
import commonjs from '@rollup/plugin-commonjs';
import typescript from 'rollup-plugin-typescript2';
import sourceMaps from 'rollup-plugin-sourcemaps';

const packageJson = require('./package.json');

const globals = {
    ...packageJson.devDependencies,
};

export default {
    input: 'src/index.ts',
    output: [
        {
            file: packageJson.main,
            format: 'cjs', // commonJS
            sourcemap: true,
            exports: 'default'
        },
        {
            file: packageJson.module,
            format: 'esm', // ES Modules
            sourcemap: true,
            exports: 'default'
        },
        {
            name: packageJson.name,
            file: packageJson.browser,
            format: 'umd', // ES Modules
            sourcemap: true,
            exports: 'default'
        },
    ],
    plugins: [
        typescript({
            rollupCommonJSResolveHack: false,
            clean: true,
        }),
        commonjs(),
        resolve(),
        sourceMaps(),
    ],
    external: Object.keys(globals)
};
