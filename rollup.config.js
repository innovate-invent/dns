import resolve from '@rollup/plugin-node-resolve';
import commonjs from '@rollup/plugin-commonjs';
import typescript from '@rollup/plugin-typescript';
import sourceMaps from 'rollup-plugin-sourcemaps';
import path from 'path';


const packageJson = require('./package.json');

const globals = {
    ...packageJson.devDependencies
};

export default {
    input: 'src/index.ts',
    output: [
        {
            file: packageJson.main,
            format: 'cjs', // commonJS
            sourcemap: true,
            exports: 'default',
            globals: {
                crypto: 'crypto',
            }
        },
        {
            file: packageJson.module,
            format: 'esm', // ES Modules
            sourcemap: true,
            exports: 'default',
            globals: {
                crypto: 'crypto',
            }
        },
        {
            name: packageJson.name,
            file: packageJson.browser,
            format: 'umd', // ES Modules
            sourcemap: true,
            exports: 'default',
            globals: {
                crypto: 'crypto',
            }
        },
    ],
    plugins: [
        typescript({
            //rollupCommonJSResolveHack: false,
            //clean: true,
            tsconfig: path.resolve(__dirname, process.env.TARGET ? "tsconfig." + process.env.TARGET + ".json" : "tsconfig.json"),
        }),
        commonjs(),
        resolve(),
        sourceMaps(),
    ],
    external: Object.keys(globals)
};
