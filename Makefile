all:
	g++ -g ccm.cpp -lcryptopp -o 3ds_ccm

clean:
	rm 3ds_ccm