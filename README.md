#Code used for MineSweeper project and results

##Setting up

1. Clone the repo
2. Run python\_requirements.py
3. Run npm\_requirements\_install.sh
4. Compile wabt tool : https://github.com/WebAssembly/wabt (Make sure it generates binary file `wabt/bin/wasm2wat`)
5. Compile Chromium browser enabling debug flags so that you can use `dump-wasm-module` JS flag to dump wasm module or use this version : https://www.cs.vu.nl/~herbertb/download/dataset/chrome-build.tar 
6. Update the config.json file

##Runing MineSweeper tool

```python minesweeper.py -t <url>```

##Testing the code locally

To test the code locally, first run a drive-by mining webapplication using
following step.

```shell
cd test-miner-app
python miner.py . 
```

Then run the minesweeper to analyze the drive-by mining webapplication that 
you hosted locally. We tested this code on Ubuntu 16.04.

```python minesweeper.py -t <url> ```


You can download the crawled data from the drive-by mining websites here: https://www.cs.vu.nl/~herbertb/download/dataset/cryptominers_dataset.tar

##Warning

This code is only for testing purposes. You are responsible for protecting yourself, your property 
and data, and others from any risks caused by this code. 

