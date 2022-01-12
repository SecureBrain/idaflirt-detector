# idaflirt-detector
idaflirt-detector is Python scripts and IDA FLIRT signatures to detect statically linked libraries from stripped ELF file.
## スクリプト
スクリプトはscriptフォルダ以下にある。
### pkg2sig.py
- OS  
UNIX系OS
- 環境  
Python 3
- 子プロセス  
wget、tar  
スクリプトと同じディレクトリ：flair??\bin\linux\pelf、flair??\bin\linux\sigmake
- 出力  
スクリプトと同じディレクトリ：pkg、lib、pat、sig、name_alternate.csv、name_ignore.txt

実行するとスクリプトがあるディレクトリにpkg、lib、pat、sigという名前でディレクトリを作成する。また作業用にtmpという名前のディレクトリを作成するが、終了時に削除する。(既にtmpがあるときには、既存のtmpも削除される。) また、スクリプトがあるフォルダにflair??\bin\linux\pelf、flair??\bin\linux\sigmakeが存在することを前提とする。

スクリプトはwgetを呼び出してpkgにディストリビューションのパッケージをダウンロードする。ダウンロードするパッケージのサブディレクトリとURLはスクリプトにハードコードされている。サブディレクトはディストリビューションの名前とバージョン番号である。保存されるファイル名はURLによって決まる。

スクリプトはダウンロードしたパッケージをtmpに展開し、libc.aとlibgcc.aをlibに名前を変えて保存する。保存される名前には先頭に「_libc_」または「_libgcc_」が付き、ディストリビューションの名前とバージョン番号に基づくスクリプトにハードコードされた名前になる。サブディレクトはIDA Proのアーキテクチャに対応する。パッケージに複数のlibc.aまたはlibgcc.aが含まれているときには、名前にパッケージを展開したときのlibc.aまたはlibgcc.aのディレクトリ名を付加する。

スクリプトはpelfを呼び出してlibにある拡張子が.aのファイルをパターンファイルに変換する。パターンファイルはライブラリと同名の拡張子が.patでpatに保存される。サブディレクトは上記のlibと同様である。同じパターンファイルが作成されたときには、最初のパターンファイルを除いて、その内容は最初のパターンファイルの名前になり、以降の処理の対象としない。

スクリプトはsigmakeを呼び出してパターンファイルをシグネチャに変換する。シグネチャはパターンファイルと同名で名前の拡張子が.sigでsigに保存される。サブディレクトは上記のpkgやlibと同様である。このファイルをIDA Proのsigフォルダ(通常は「%ProgramFiles%\IDA Pro ?.?\sig」)にコピーすることでIDA Proのシグネチャとして利用できる。

スクリプトはスクリプトがあるディレクトリに「name_alternate.csv」が存在しなければ作成する。スクリプトはスクリプトがあるディレクトリに「name_ignore.txt」が存在しなければ作成する。
### chksig.py
- OS  
Windows
- 環境  
Python 3(IDA Python)
- 入力  
検体と同じパス：*_chksig.json  
IDA Pro：*.sig
- 出力  
検体と同じパス：*_chksig.json

スクリプトはコマンドラインまたはIDA Pythonとして実行可能である。
#### コマンドライン
コマンドラインから引数としてELFファイルを指定する。スクリプトはIDA Proを起動し、本スクリプトをIDA Pythonとして実行する。スクリプトは静的にリンクされたライブラリが見つかるか、静的にリンクされたライブラリがないと確定するまで、IDA Pythonの実行を繰り返す。IDA Proは「%ProgramFiles%\IDA Pro*」にインストールされていることを前提とする。
##### オプション
- -f、--force  
既存のJSONがあるならば削除する。
- -i、--ignore  
--ignore-entropyと--ignore-machine、--ignore-stripが有効になる。
- --ignore-entropy  
このオプションがないときにはファイル全体のエントロピーが7.2未満のファイルを対象とする。このオプションを付けるとエントロピーに関係なくすべてのファイルが対象となる。
- --ignore-machine  
このオプションがないときにはCPUがARM、MIPS、Renesas SH、PowerPC or cisco 4500、x86-64、Intel 80386の検体だけでライブラリを特定する。このオプションを付けるとすべてのCPUが対象となる。
- --ignore-strip  
このオプションがないときには動的にライブラリをリンクしないstripされた検体だけでライブラリを特定する。このオプションを付けると動的リンクやstripに関係なく対象となる。
#### IDA Python
スクリプトはIDBファイルと同じ名前でファイル名の末尾および拡張子が「_chksig.json」のJSONファイルがないときには、すべてのシグネチャを順番に適用し、各シグネチャで検出した関数の数をJSONファイルに書き込む。スクリプトはJSONファイルが存在するときには読み込む。スクリプトはJSONのdetermineの値がなくestimateの値が最も大きいシグネチャを適用し、シグネチャで検出した関数の数をdetermineに書き込む。

determineの値が他のestimateおよびdetermineの値よりも大きいならば、そのライブラリが静的にリンクされているとみなす。
### prepare.py
- OS  
Windows
- 環境  
Python 3(IDA Python)
- 入力  
IDBと同じパス：*_chksig.json  
IDA Pro：*.sig  
スクリプトと同じフォルダ：prepare.txt、name_alternate.csv

スクリプトをIDA Pythonとして実行すると、下記の関数を実行する。またコマンドラインから実行すると引数でしていたprepare.txtを解析してソートした結果を出力する。
#### functionalize_single_instruction()
スクリプトはすべてのアドレスを走査し、関数に属していないコード領域があるときには、その領域を1つの関数にする。
#### apply_signature()
スクリプトはIDBファイルと同じ名前でファイル名の末尾および拡張子が「_chksig.json」のJSONファイルを読み込む。このJSONは辞書であり鍵resultの値の辞書の値で示されるシグネチャを適用する。
#### true_up_function_name()
スクリプトはスクリプトと同じフォルダで名前が「name_alternate.csv」のファイルを読み込む。このファイルに基づき、関数の名前を標準化する。また関数のライブラリのフラグを有効にする。
#### get_c_main()
スクリプトは名前が「main」、または名前が「main_<16進数アドレス>」の関数があるならば、そのアドレスを返す。該当する関数がないときにはBADADDRを返す。該当する関数が複数あるときの動作は不定である。
#### register_c_main()
スクリプトはget_c_mainがBADADDRを返すときには、C言語のmain関数を推定し、その関数を定義する。エントリーポイントからデータとして参照される名前がない関数が1つしかないときには、その関数をmainとみなす。該当する関数がないときまたは複数あるときにはmainの検出は失敗する。スクリプトは検出した関数の名前を「main_<16進数アドレス>」に変更する。
#### load_type_library()
スクリプトは64ビットのときにはタイプライブラリの「gnuunx64」、それ以外では「gnuunx」をロードする。
#### apply_function_type()
スクリプトはスクリプトと同じフォルダで名前が「prepare.txt」のファイルを読み込む。スクリプトはこのファイルに基づき、関数や変数の名前が一致するときには型を設定する。スクリプトはスクリプトと同じフォルダで名前が「name_alternate.csv」のファイルを読み込むことができるならば、このファイルに基づいて標準化されていない名前にも対応する。
## ファイル形式
### *_chksig.json
ファイルはJSONであり、その内容は辞書である。辞書の鍵はestimate、determine、resultである。estimateとdetermineは辞書であり、鍵はライブラリの名前、値は検出した関数の数である。estimateは1回のスクリプトの実行でライブラリを順番に適用したときに検出した関数の数であり、determineは初めてライブラリを適用したときに検出した関数の数である。resultは辞書であり、鍵はライブラリの接頭辞、値は適用すべきライブラリの名前である。resultがあるならば、ライブラリを特定する処理は終了している。
## 成果物
成果物はスクリプトを実行した結果、生成されたファイルでありdeliverableフォルダ以下にある。
### name_alternate.csv
同じ関数に複数の名前がある場合、その関数の名前を「,」で区切って1行に出力する。各行は名前が短い順、辞書順にソートされる。本研究では最初の名前を関数の標準の名前とみなす。
### name_ignore.txt
各行はlibgcc.aにある関数の名前である。
### sig/{arm,mc68k,mips,pc,ppc,sh3}
IDA Proのsigフォルダ(通常は「%ProgramFiles%\IDA Pro ?.?\sig」)にコピーすることでIDA Proのシグネチャとして利用できる。
## Copyright
Copyright (c) 2022 SecureBrain.
## 謝辞
本研究は総務省の「電波資源拡大のための研究開発(JPJ000254)」における委託研究「電波の有効利用のためのIoTマルウェア無害化／無機能化技術等に関する研究開発」によって実施した成果を含みます。
