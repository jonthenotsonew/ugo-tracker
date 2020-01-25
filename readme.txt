Ugo Tracker

Ugo Tracker is a UDP tracker written for Python 3. I wrote it because we once had to transfer multiple GB of data, but we didn't want to register the torrent in a public tracker.

It's named after a mountain in the Philippines.

* Dependencies

pip3 install bitarray
pip3 install redis
pip3 install bencode.py

* Tests (you need redis for this)

python3 test_ugo_tracker3.py

* Running

python3 ugo_tracker3.py

* Compatibility

Anaconda Python 3.7 for Windows