import pytest
import sure  # noqa: F401


from incountry import InCrypto, SecretKeyAccessor, decrypt_record, encrypt_record


from ..utils import omit


PREPARED_PAYLOADS = [
    (
        {
            "record_key": "976143aa1fd12b9ad7449fd9d3a6d25347d71b890b49d4fb5c738e798238865f",
            "body": f"2:IGJNCmV+RXZydaPxDjjhZ80/6aZ2vcEUZ2GuOzKgVSSdM6gYf5RPgFbyLqv+7ihz0CpYFQQWf9xkIyD/u3VYky8"
            f"dWLq+NXcE2xYL4/U7LqUZmJPQzgcQCABYQ/8vOvUEcrfOAwzGjR6etTp1ki+79JmCEZFSNqcDP1GZXNLFdLoSUp1X2wVlH9uk"
            f"hJ4jrE0cKDrpJllswRSOz0BhS8PA/73KNKwo718t7fPWpUm7RkyILwYTd/LpPvpXMS6JypEns8fviOpbCLQPpZNBe6zpwbFf3"
            f"C0qElHlbCyPbDyUiMzVKOwWlYFpozFcRyWegjJ42T8v52+GuRY5",
            "key2": "abcb2ad9e9e0b1787f262b014f517ad1136f868e7a015b1d5aa545b2f575640d",
            "key3": "1102ae53e55f0ce1d802cc8bb66397e7ea749fd8d05bd2d4d0f697cedaf138e3",
            "profile_key": "f5b5ae4914972ace070fa51b410789324abe063dbe2bb09801410d9ab54bf833",
            "range_key1": 100500,
            "version": 0,
        },
        {
            "record_key": "InCountryKey",
            "key2": "InCountryKey2",
            "key3": "InCountryKey3",
            "profile_key": "InCountryPK",
            "body": '{"data": "InCountryBody"}',
            "range_key1": 100500,
        },
        "InCountry",
        "password",
    ),
    (
        {
            "record_key": "976143aa1fd12b9ad7449fd9d3a6d25347d71b890b49d4fb5c738e798238865f",
            "profile_key": "f5b5ae4914972ace070fa51b410789324abe063dbe2bb09801410d9ab54bf833",
            "range_key1": 100500,
            "range_key2": 10050,
            "range_key3": 1005,
            "range_key4": 100,
            "range_key5": 10,
            "range_key6": 1,
            "range_key7": 10,
            "range_key8": 100,
            "range_key9": 1005,
            "range_key10": 10050,
            "service_key1": "b2d95d1ccfeb1a17c99b74685f7fd4c33647b97cb0559c267a4afcd6f649f3a8",
            "service_key2": "9bbc39b2617cbd9fc0290f93c7bbd1772f1a2a45f48ae8dc1a9544d75159c7a2",
            "key1": "daf5914655dc36b7f6f31a97a05205106fdbd725e264235e9e8b31c66489e7ed",
            "key2": "abcb2ad9e9e0b1787f262b014f517ad1136f868e7a015b1d5aa545b2f575640d",
            "key3": "1102ae53e55f0ce1d802cc8bb66397e7ea749fd8d05bd2d4d0f697cedaf138e3",
            "key4": "08a46eb74e0621208a41cf982b9da83e564a1d448997c5c912477ff79ec4c0e3",
            "key5": "cb86e1358566c9f6c1a52106b32a085b5f02aa8330d3f538ddf55cd599a320f7",
            "key6": "5048f7bae5308ca05006ef63025d4243beddbf431f7eff43ac927e471656d1ed",
            "key7": "aa9e0b00099734cafeda1b13393422a381596dc3fd189ee598791fa95f46bce4",
            "key8": "54933d4eb2e2d2c1e7ab9344e23a233ee9c537876929d5e265d45ae789b03f6c",
            "key9": "c0e91efa56683cf7f1f0f99b2791e4719e7f70018c6e3938ebaff5735d3c275f",
            "key10": "9f54258b7136a70f61891f162243e11930d5cedb3ca89682bab9f28fbedda9b6",
            "precommit_body": "2:iqFsqhqby5rX5YAsFnboXoMwSBX7b8JSybs6INJTSMNBSZIulv44hyYw2XlENtOWTCV1Sn1uz"
            f"M4H4ekTy3vXhTyzbndWBdSWNXcT8mLUDZcByyGJhKunvuvr9B1Bk5GghNzuEvriVsV08LEg",
            "body": "2:0Xxd0QYOXstTmrA1Erqm6F/jxt83IHFFHqJPf+QuMpwOObh+OaJ1hCjLLGi2GVnBXENQ5sIt92ayemBXr5J"
            f"EY2CNUI9lp18gOim+aXveWH1FN8yk5HYqoSyOb5CkJHvp73+AaFmpzTJA3Zxy7z7rfZE2ByCwGtX454iY35jQcUGr1Zp"
            f"o3m4BX2Y8Rc+RYvAO0J+1y6iDnaNk228d0QwDK4VRISslct+vp7T+O/fnOuyTZzoy/2IoUuvHpkhGsKB2sA+elqCMHz6"
            f"4HGlbGL1OWMmChmQ4R3Ax+/ddzd3xorUQdyz0S1L0YoByE/vCAgGMCkXkQ7kSnqFsRLyJPK4tZWen+G7pt4SdLHoD60v"
            f"h8QrGtPXVQe4P9HeNCwZXOyhpZbTKvHRXIzsmzGud7Z6rU4DGSBEoeWXcVKIgQ7H0sBCHFZ6ixsw0fb/ciw66HGS/06t"
            f"yjrWyMsq7HsaOkL01bzaRM9SMeZZskHDGsi4fOvt498SvKF2VT28PMWH8h4Wj24q7o18Ms7NrhnkqDql11FsKLb/O6hc"
            f"Ko5c9GzsSkYN+7KoPwHcj+eWs0Odu4BL2xq7VJiIjCw+25pqlXSpyKV0QTUSXI31VTNoqRRMpBlM06n4SC6SidQfRiiW"
            f"XqptJEhLA9g==",
            "version": 0,
            "is_encrypted": True,
        },
        {
            "record_key": "InCountryKey",
            "body": '{"data": "InCountryBody"}',
            "precommit_body": '{"test": "test"}',
            "key1": "InCountryKey1",
            "key2": "InCountryKey2",
            "key3": "InCountryKey3",
            "key4": "InCountryKey4",
            "key5": "InCountryKey5",
            "key6": "InCountryKey6",
            "key7": "InCountryKey7",
            "key8": "InCountryKey8",
            "key9": "InCountryKey9",
            "key10": "InCountryKey10",
            "profile_key": "InCountryPK",
            "service_key1": "service1",
            "service_key2": "service2",
            "range_key1": 100500,
            "range_key2": 10050,
            "range_key3": 1005,
            "range_key4": 100,
            "range_key5": 10,
            "range_key6": 1,
            "range_key7": 10,
            "range_key8": 100,
            "range_key9": 1005,
            "range_key10": 10050,
        },
        "InCountry",
        "password",
    ),
    (  # schema 2.3
        {
            "record_key": "976143aa1fd12b9ad7449fd9d3a6d25347d71b890b49d4fb5c738e798238865f",
            "profile_key": "f5b5ae4914972ace070fa51b410789324abe063dbe2bb09801410d9ab54bf833",
            "parent_key": "48734579d0358c2ec2f9dae81cf963f9848d0f3eebe0dd49fa5c5177a76d6e83",
            "range_key1": 100500,
            "range_key2": 10050,
            "range_key3": 1005,
            "range_key4": 100,
            "range_key5": 10,
            "range_key6": 1,
            "range_key7": 10,
            "range_key8": 100,
            "range_key9": 1005,
            "range_key10": 10050,
            "service_key1": "b2d95d1ccfeb1a17c99b74685f7fd4c33647b97cb0559c267a4afcd6f649f3a8",
            "service_key2": "9bbc39b2617cbd9fc0290f93c7bbd1772f1a2a45f48ae8dc1a9544d75159c7a2",
            "key1": "daf5914655dc36b7f6f31a97a05205106fdbd725e264235e9e8b31c66489e7ed",
            "key2": "abcb2ad9e9e0b1787f262b014f517ad1136f868e7a015b1d5aa545b2f575640d",
            "key3": "1102ae53e55f0ce1d802cc8bb66397e7ea749fd8d05bd2d4d0f697cedaf138e3",
            "key4": "08a46eb74e0621208a41cf982b9da83e564a1d448997c5c912477ff79ec4c0e3",
            "key5": "cb86e1358566c9f6c1a52106b32a085b5f02aa8330d3f538ddf55cd599a320f7",
            "key6": "5048f7bae5308ca05006ef63025d4243beddbf431f7eff43ac927e471656d1ed",
            "key7": "aa9e0b00099734cafeda1b13393422a381596dc3fd189ee598791fa95f46bce4",
            "key8": "54933d4eb2e2d2c1e7ab9344e23a233ee9c537876929d5e265d45ae789b03f6c",
            "key9": "c0e91efa56683cf7f1f0f99b2791e4719e7f70018c6e3938ebaff5735d3c275f",
            "key10": "9f54258b7136a70f61891f162243e11930d5cedb3ca89682bab9f28fbedda9b6",
            "key11": "7ff26763def85a1a89c0fdb19233e29fb56596678f62f6e41910b169f093ca67",
            "key12": "89976091da7295197e2308b75e44bc041dbbf168c24a8e966ad36fb7abfce2d5",
            "key13": "0f29faa621589f9697cea59702b2a004e0218f76f31481dec52db49399eda2c7",
            "key14": "1ac2ea997a372fbd0e151c4fc7afc8a691357199f084476f5d5be72ab34f95af",
            "key15": "a24189e052ff879096e49b9c49a6ef89fbde0d9a7bedece0888d562ae7e30ba7",
            "key16": "cdf7f7f7e636731cf84d4fced224a7fea12789affc80c3625d34c0b0225a95f1",
            "key17": "e00d696f96834844980da61d99cc2f9e9986a4708e098232f38c3a6882c7a2bd",
            "key18": "84d49a44022203031f83598591301bddcb3086c300414cbec552ad22ba01abeb",
            "key19": "3eaec397977e9a6edbfb88de2463a05036d279157f15bc6f41dc1d8ea5ef91fb",
            "key20": "301597b144c6d48f8a3b20190487647461610e5e438a88fbc9c201c80a3dc039",
            "precommit_body": "2:cY5Yu3ouMehX+LRUuNFGAutdiz+a+LvrB9moG0rLxCGOW/nJMeyct2r/Ug9wPkwO6lVtoJwLO"
            f"al1kyji1G97+EdaFT8cwrzQnmsZ/9KZbIvcSBh6iyhXdntjQfboXpKwyXGdAQETRqztKlXm",
            "body": "2:eakwsLxHg142RUA7+h1m+S+LDgxz8N8AzupswNxcIJcr2beMxH86oDlOctdo0QAPLcUKn8wENZQ8igPPm4+"
            f"l9rK2v0nDaF1rhsR/BVmEIga/20VfYrqlbOt5zWtGf9/P5I4jLrTlpm8lC7VICOquvtWYYB83tIEOTgYOD4eRTDAcXkX"
            f"vfNM3G7p+xodAS8aoXoWCVme+cpFpa5FSWMas8if25tQ7MKTkCSpJwP6h3USu5tDKkaRVpqPivU2fMNETkN+M/97gOxb"
            f"vWv0jB63WEi2KHSMF5xWVWHReTsNobbxqryQXkfwH7DEf90Q1CcXvilrVV5qhB1TQiJwgSpggplcxSeIHozjuFLsKe57"
            f"vbkdoX0aXvIrtuyxxg6b3p+MYGJFLFJ0vwh7GAYOC5F4CQQpMVXH9lGzvZNd9gUClGAiew4e+XtRvO+ZZRJIYf86sL1m"
            f"KvXtYGzun4OV22QspxW1H1wfCZzLZfDnGV9LvP5LTDUseQTaQ21Zp9xgjC6ytgfbPk/TYdwajkmYRQX9/gYam4h7oHv1"
            f"9hUD/I+4Rw5zzfyqp7695vW/z23fvsNbGJlEsMN+3idlKSdXenA7JffU1std2f4CQ1PCI5QIrYi3XwgLQ7yIxM6yZ19W"
            f"LSiGuckoM/QP7txc3yFu2+nR307zwsnTlVEw9IYOftG+f+wDgt9PMZmZv23nS4e/RLJmiHgjTkAmVpipKU0X4LndlmZK"
            f"SKGGu2RkYFtG8D7Gsh3YcsHNm8L9HoIqdvKaJQTVjdFWyj/HGs/u19iOo//h/od1B3PnzNelkyV1b0tuDl5RNsug5VZB"
            f"yu7bpfebud1QfepEu5qda0rbTJm1/2gyejnB6u90Vti3c+ozReAaKo7ZNQskbJopprr3cOB9uTN/t7O0/FQxTNHrN4zJ"
            f"urU6NN15f0/Vqkh0IKTTcfzd5EOjZUZp98/dIrRKjap42hB5AwycPmPJE3yZPhsw9f5ARBWlWR1SSJgORvcL3Nt6QJKZ"
            f"ggd/hYj/D3XICYXEdqmlxnpKkj/vCZYoUFR5jLxQ7I/QiNRmBMXVlfIdCCwC/6fqfaDWRpbPEgp9P6OdLK1af"
            f"CAU2UA==",
            "version": 0,
            "is_encrypted": True,
        },
        {
            "record_key": "InCountryKey",
            "body": '{"data": "InCountryBody"}',
            "precommit_body": '{"test": "test"}',
            "key1": "InCountryKey1",
            "key2": "InCountryKey2",
            "key3": "InCountryKey3",
            "key4": "InCountryKey4",
            "key5": "InCountryKey5",
            "key6": "InCountryKey6",
            "key7": "InCountryKey7",
            "key8": "InCountryKey8",
            "key9": "InCountryKey9",
            "key10": "InCountryKey10",
            "key11": "InCountryKey11",
            "key12": "InCountryKey12",
            "key13": "InCountryKey13",
            "key14": "InCountryKey14",
            "key15": "InCountryKey15",
            "key16": "InCountryKey16",
            "key17": "InCountryKey17",
            "key18": "InCountryKey18",
            "key19": "InCountryKey19",
            "key20": "InCountryKey20",
            "parent_key": "InCountryParentKey",
            "profile_key": "InCountryPK",
            "service_key1": "service1",
            "service_key2": "service2",
            "range_key1": 100500,
            "range_key2": 10050,
            "range_key3": 1005,
            "range_key4": 100,
            "range_key5": 10,
            "range_key6": 1,
            "range_key7": 10,
            "range_key8": 100,
            "range_key9": 1005,
            "range_key10": 10050,
        },
        "InCountry",
        "password",
    ),
]


@pytest.mark.parametrize(
    "stored_record, expected_record, env_id, password",
    PREPARED_PAYLOADS,
)
@pytest.mark.happy_path
def test_dec_stored_data(stored_record, expected_record, env_id, password):
    secret_accessor = SecretKeyAccessor(lambda: password)
    cipher = InCrypto(secret_accessor)

    decrypted_record = decrypt_record(cipher, stored_record)

    assert omit(decrypted_record, "version", "is_encrypted") == expected_record


@pytest.mark.parametrize(
    "stored_record, expected_record, env_id, password",
    PREPARED_PAYLOADS,
)
@pytest.mark.happy_path
def test_enc_data(stored_record, expected_record, env_id, password):
    secret_accessor = SecretKeyAccessor(lambda: password)
    cipher = InCrypto(secret_accessor)

    encrypted_record = encrypt_record(cipher, expected_record, env_id)

    assert omit(encrypted_record, "body", "is_encrypted", "precommit_body") == omit(
        stored_record, "body", "is_encrypted", "precommit_body"
    )
