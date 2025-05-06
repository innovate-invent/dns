const resolve = require('@rollup/plugin-node-resolve');
const commonjs = require('@rollup/plugin-commonjs');
const typescript = require('@rollup/plugin-typescript');
//const sourceMaps = require('rollup-plugin-sourcemaps');
const path = require('path');


const packageJson = require('./package.json');

const globals = {
    ...packageJson.devDependencies
};

module.exports = {
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
        //sourceMaps(),
    ],
    external: Object.keys(globals)
};
