const EXTRA_GCM_VECTORS: &[GcmVector] = &[
    // Source: Wycheproof (tcId=92)
    GcmVector {
        key: "29d3a44f8723dc640239100c365423a312934ac80239212ac3df3421a2098123",
        nonce: "00112233445566778899aabb",
        pt: "",
        aad: "aabbccddeeff",
        ct: "",
        tag: "2a7d77fa526b8250cb296078926b5020",
    },
    // Source: Wycheproof (tcId=93)
    GcmVector {
        key: "80ba3192c803ce965ea371d5ff073cf0f43b6a2ab576b208426e11409c09b9b0",
        nonce: "4da5bf8dfd5852c1ea12379d",
        pt: "",
        aad: "",
        ct: "",
        tag: "4771a7c404a472966cea8f73c8bfe17a",
    },
    // Source: Wycheproof (tcId=95)
    GcmVector {
        key: "51e4bf2bad92b7aff1a4bc05550ba81df4b96fabf41c12c7b00e60e48db7e152",
        nonce: "4f07afedfdc3b6c2361823d3",
        pt: "be3308f72a2c6aed",
        aad: "",
        ct: "cf332a12fdee800b",
        tag: "602e8d7c4799d62c140c9bb834876b09",
    },
    // Source: Wycheproof (tcId=96)
    GcmVector {
        key: "67119627bd988eda906219e08c0d0d779a07d208ce8a4fe0709af755eeec6dcb",
        nonce: "68ab7fdbf61901dad461d23c",
        pt: "51f8c1f731ea14acdb210a6d973e07",
        aad: "",
        ct: "43fc101bff4b32bfadd3daf57a590e",
        tag: "ec04aacb7148a8b8be44cb7eaf4efa69",
    },
    // Source: Wycheproof (tcId=97)
    GcmVector {
        key: "59d4eafb4de0cfc7d3db99a8f54b15d7b39f0acc8da69763b019c1699f87674a",
        nonce: "2fcb1b38a99e71b84740ad9b",
        pt: "549b365af913f3b081131ccb6b825588",
        aad: "",
        ct: "f58c16690122d75356907fd96b570fca",
        tag: "28752c20153092818faba2a334640d6e",
    },
    // Source: Wycheproof (tcId=98)
    GcmVector {
        key: "3b2458d8176e1621c0cc24c0c0e24c1e80d72f7ee9149a4b166176629616d011",
        nonce: "45aaa3e5d16d2d42dc03445d",
        pt: "3ff1514b1c503915918f0c0c31094a6e1f",
        aad: "",
        ct: "73a6b6f45f6ccc5131e07f2caa1f2e2f56",
        tag: "2d7379ec1db5952d4e95d30c340b1b1d",
    },
    // Source: Wycheproof (tcId=99)
    GcmVector {
        key: "0212a8de5007ed87b33f1a7090b6114f9e08cefd9607f2c276bdcfdbc5ce9cd7",
        nonce: "e6b1adf2fd58a8762c65f31b",
        pt: "10f1ecf9c60584665d9ae5efe279e7f7377eea6916d2b111",
        aad: "",
        ct: "0843fff52d934fc7a071ea62c0bd351ce85678cde3ea2c9e",
        tag: "7355fde599006715053813ce696237a8",
    },
    // Source: Wycheproof (tcId=100)
    GcmVector {
        key: "b279f57e19c8f53f2f963f5f2519fdb7c1779be2ca2b3ae8e1128b7d6c627fc4",
        nonce: "98bc2c7438d5cd7665d76f6e",
        pt: "fcc515b294408c8645c9183e3f4ecee5127846d1",
        aad: "c0",
        ct: "eb5500e3825952866d911253f8de860c00831c81",
        tag: "ecb660e1fb0541ec41e8d68a64141b3a",
    },
    // Source: Wycheproof (tcId=101)
    GcmVector {
        key: "cdccfe3f46d782ef47df4e72f0c02d9c7f774def970d23486f11a57f54247f17",
        nonce: "376187894605a8d45e30de51",
        pt: "e28e0e9f9d22463ac0e42639b530f42102fded75",
        aad: "956846a209e087ed",
        ct: "feca44952447015b5df1f456df8ca4bb4eee2ce2",
        tag: "082e91924deeb77880e1b1c84f9b8d30",
    },
    // Source: Wycheproof (tcId=102)
    GcmVector {
        key: "f32364b1d339d82e4f132d8f4a0ec1ff7e746517fa07ef1a7f422f4e25a48194",
        nonce: "5a86a50a0e8a179c734b996d",
        pt: "43891bccb522b1e72a6b53cf31c074e9d6c2df8e",
        aad: "ab2ac7c44c60bdf8228c7884adb20184",
        ct: "43dda832e942e286da314daa99bef5071d9d2c78",
        tag: "c3922583476ced575404ddb85dd8cd44",
    },
    // Source: Wycheproof (tcId=103)
    GcmVector {
        key: "ff0089ee870a4a39f645b0a5da774f7a5911e9696fc9cad646452c2aa8595a12",
        nonce: "bc2a7757d0ce2d8b1f14ccd9",
        pt: "748b28031621d95ee61812b4b4f47d04c6fc2ff3",
        aad: "972ab4e06390caae8f99dd6e2187be6c7ff2c08a24be16ef",
        ct: "a929ee7e67c7a2f91bbcec6389a3caf43ab49305",
        tag: "ebec6774b955e789591c822dab739e12",
    },
    // Source: Wycheproof (tcId=104)
    GcmVector {
        key: "6efca98126918ab564d88c6bec02e8998b2be50e3f906ff9adfdd185f373e756",
        nonce: "4abd6cfc83bd06b11efaa2a7",
        pt: "bbec79c086d41e602d090f7e40494d6bf3faa1dc6df0ab8a88ea5d35d426b248c2ad880351e223f6170d37cc9655e10459e59cbd6d1c092ed31d72ccc7af20",
        aad: "",
        ct: "97b4c73a4d8b5b21bc4b50dbb70dfa77b1a7bf0bbe7cf16ecf5bb60ba8070acc5740780435ed145a62a613dd9881b721168fbb3f5af385ee5d4f856cf93cba",
        tag: "27ac8c4010d8e81b7051ceb06b30fe2d",
    },
    // Source: Wycheproof (tcId=105)
    GcmVector {
        key: "5b1d1035c0b17ee0b0444767f80a25b8c1b741f4b50a4d3052226baa1c6fb701",
        nonce: "d61040a313ed492823cc065b",
        pt: "d096803181beef9e008ff85d5ddc38ddacf0f09ee5f7e07f1e4079cb64d0dc8f5e6711cd4921a7887de76e2678fdc67618f1185586bfea9d4c685d50e4bb9a82",
        aad: "",
        ct: "c7d191b601f86c28b6a1bdef6a57b4f6ee3ae417bc125c381cdf1c4dac184ed1d84f1196206d62cad112b038845720e02c061179a8836f02b93fa7008379a6bf",
        tag: "f15612f6c40f2e0db6dc76fc4822fcfe",
    },
    // Source: Wycheproof (tcId=106)
    GcmVector {
        key: "81b6b27e5ed90ab99fe6756d4cb41e3f07269687f5afabdb426e29096b5e4466",
        nonce: "13e727486031cca21f733375",
        pt: "9a95a23cfb1e35d89a7597570df0fb0efcbb7429f53bebcbbfa49fa247b251a8508ad497066855d08688576188e4ffb12d1d084dcabec3d57806daf215dcc97edd",
        aad: "",
        ct: "7ede7368bca3c93d9f1d7f7750d6e44b1cb92c30e3c9834b0b69efd2470911644ae6f6d75715e13aea8781f8da611a13ac6364c406c1a715b7e97acb22b6e6156e",
        tag: "74e20a93802f43407c8989a37f013802",
    },
    // Source: Wycheproof (tcId=107)
    GcmVector {
        key: "ea1d436f6359caec010789fa94fe08b167c3e497d8917282f47ad2a8f95fd0f1",
        nonce: "73fe022202767af834e32126",
        pt: "adf9b6df5c5cc9473e0bb579f9a6aad396f93d28bf83e98136f978cfb9d501d09ef778c122b43c876c22e40d74a48d908978465a06be9e80891710c8c2690a762bc9eb8bcb2aa2707db149abafb9c17c1f0b68c7adcea98aebf4c6a39e5a8f693133eaaa5bb0b3708720d7b86424101bad56aa190c67d25fe35a4a34e1f4fd",
        aad: "",
        ct: "2e6b19520d9c91e41f523bfd80cb3d577df762879b04a586b865280bac651102fa60164b8586f91c02b2151cc2fd29f4c6e92839cdd873be12c1443141f8bcb8754965aec7c0829fb391e56563ba76e896ec81932b5efbad23bb965ebbf8d8fda98f9cbd48f37b2c46db609e40768266c2b36a7810d2b79133f377d0377b41",
        tag: "f9a0eba513904c4a7168d762000f34be",
    },
    // Source: Wycheproof (tcId=108)
    GcmVector {
        key: "d7addd3889fadf8c893eee14ba2b7ea5bf56b449904869615bd05d5f114cf377",
        nonce: "8a3ad26b28cd13ba6504e260",
        pt: "c877a76bf595560772167c6e3bcc705305db9c6fcbeb90f4fea85116038bc53c3fa5b4b4ea0de5cc534fbe1cf9ae44824c6c2c0a5c885bd8c3cdc906f12675737e434b983e1e231a52a275db5fb1a0cac6a07b3b7dcb19482a5d3b06a9317a54826cea6b36fce452fa9b5475e2aaf25499499d8a8932a19eb987c903bd8502fe",
        aad: "",
        ct: "53cc8c920a85d1accb88636d08bbe4869bfdd96f437b2ec944512173a9c0fe7a47f8434133989ba77dda561b7e3701b9a83c3ba7660c666ba59fef96598eb621544c63806d509ac47697412f9564eb0a2e1f72f6599f5666af34cffca06573ffb4f47b02f59f21c64363daecb977b4415f19fdda3c9aae5066a57b669ffaa257",
        tag: "5e63374b519e6c3608321943d790cf9a",
    },
    // Source: Wycheproof (tcId=109)
    GcmVector {
        key: "7f7c5804a680f61924966725dba2a80d85267c2e03c7c234b045b24ec8e23528",
        nonce: "2d9bf8b636f337d265b0904c",
        pt: "e2f85fb176840c38345da0f0f8db6cdbc45a123165f244ff5389fe65bf341fa131130751b5c739a9931d5a57b141dc7b5b0c5a2ca07331c2dc04b2657b0289878dea0ef7d5601465b78a65795f0f3181304e58a261feb1d394f3c33cabae189941755d7654bb7bef08c31bd2c5ce1203eebc015ae040da2a851c2ba3c62e699356",
        aad: "",
        ct: "d7380d10b22c3ae584531e9e4ee73d387f69dbbb3d3d9fdb4971ed2750b31913f79e4c00cf1b76933bbb75d39d8a6429a2528e9bd60e65fa6ffff9e01a8758e7b58409fa3f370cc32a63aa60a54c36d733e8f6dfccd5c3120d05c6e33140c00562865532b2c689de98769d3386e7a3ae679e404e062536ca046261211a426fb586",
        tag: "753f6c57c0cc2a075e68d082f6e83590",
    },
    // Source: Wycheproof (tcId=110)
    GcmVector {
        key: "01e75ae803d3045e6b28b7f67937eee2d8d98f77b4892d48ab1f15f57fa88bbe",
        nonce: "6902e8f0ef1e9ec60a3e46f0",
        pt: "32dde3b9bc671fad1265b26cad3d8dd0f099134f6755f98613024e1bd10da9a62bad01a997f973101e855ee1c7e60e6b6aa1df9d80fa567d0ccca0f956680be76ed37c71fdedef560e2523e8c5fdb9516250017304f8ff416b9b8e5d17c1f062ded4616ea9d462ed6ca0dfddb9f5295b7a127c0825ffab56ea4983c01eec867f93e24a18be48ceb540986c530104fd466318eb812eb42fd04355615f92503e53799742cdc71830eaa44aeec914b6ff1cbb4f6f81ab595078331d645c8d083b469731174a706b1666e5e450cb62671067032a566f597b9866b71514a409e38fcabe844964581b3ab5152696b76e49ace66581d21f512e28e077c44948a65260",
        aad: "",
        ct: "6323ddbf9eb0463714d5857d1841a9f65529516c2f412956bc835f4f252d22a2ce743f21767fcb28859882b570ca053970b72e86f451ff0c77e87f3a03c0536b3859394fce324442ac197874f81a2ce649b99feb442e23123f7ab361d2ce6768a1badb30c509e79bee9277d378fadaa64e77e26f726df86110526530cd439429b017ae2bcec8cc24f994f5885a8a76fab6339c7054df76aa6f450193a635d21d22f71f1ae6856036e6caaeed8840bbfbc8236c25a31e775cba5f6e189fcbc3e96970ca5378fd5c29a712f5dc17641ad88ab566d8c78fff1bb57f9b2f7c9db838b4307c63e04a73d3ef8121f48932ec318dffaead58a83a7f79bc44a1587990",
        tag: "0c92bb5291e981bf562293877f4ddb5f",
    },
    // Source: Wycheproof (tcId=111)
    GcmVector {
        key: "dc4dbf811f9509e33a45a8a0743e9391de333f69c56ee4f0fe90ce21c238ee59",
        nonce: "1859d3ba4710cdd300baa029",
        pt: "df91c48591f4cae8c4d659d024dfd0a3535981487764bf19b012713e6ac6d578aa0b3a51d7ac97cd503fdc8682cabdb6a5256e9890458356f39b9749f6ab158112fbe4f91acd333477998b9f0d7cc0be2d40acfa5103adc1b0d0a5cc94733d703e0d8c26e09e9d079fa6a65cf35240a16280826ab7c0d8ac5882c89e58444233c2f60aaae0cbd1a7ed850065242a9378c340232fd86f1fd52a92c960a9a86f529f431acf3aa94133785803f4ac1a22378332daa22dea3d34d2fdb7c308fa44ab93b3fb02f428be22fad6c0b10c138af97b92a199296dd947c93fbc40674c34c5623d26d9c90dc6b3357018b9f9250fb4dd5c11518191a236745a2bd42f863766",
        aad: "",
        ct: "9c511d08f244cb6971a39b70639c4a53ae48254fcb3d2eea4796ecc996f1fe26a8e30932258a48fe4237e5bfb0e1320dc591256dc83cd56dbf5d9b377b7805b7fac0497b2f99e3310e9e2cc8009141a82f26f8a02299d64138bb1fe8a1243df3e9fb37b52bd3c2cc19f543b3f4928e5a73730a7a6e6d75919d117d3dfe10e863a9846b2ca260de5dddba7ceac37019e615b89a2ab94df8d1a790749998cb8531fef1ef5f8a28a8ad60e813f7e78412ca4d95b9604a24a16e4a3ca8ee33bfbb7809048014943e5fd7966a7db214e052d1cc546a6da72ec89d1c3398aefdcb881dfc3d800b7323abcd7583e9c8a31f03b6995d4aeac17c5a56d8af492a2b108fe3",
        tag: "17090ce50e35244a59bafc80eba5dae5",
    },
    // Source: Wycheproof (tcId=112)
    GcmVector {
        key: "317ba331307f3a3d3d82ee1fdab70f62a155af14daf631307a61b187d413e533",
        nonce: "a6687cf508356b174625deaa",
        pt: "32c1d09107c599d3cce4e782179c966c6ef963689d45351dbe0f6f881db273e54db76fc48fdc5d30f089da838301a5f924bba3c044e19b3ed5aa6be87118554004ca30e0324337d987839412bf8f8bbdd537205d4b0e2120e965373235d6cbd2fb3776ba0a384ec1d9b7c631a0379ff997c3f974a6f7bbf4fd23016211f5fc10acadb5e400d2ff0fdfd193f5c6fc6d4f7271dfd1349ed80fbedaebb155b9b02fb3074495d55f9a2455f59bf6f113191a029c6b0ba75d97cdc0c84f131836337f29f9d96ca448eec0cc46d1ca8b3735661979d83302fec08fffcf5e58f12b1e7050657b1b97c64a4e07e317f554f8310b6ccb49f36d48c57816d24952aada711d4f",
        aad: "",
        ct: "d7eebc9587aa21136fa38b41cf0e2db03a7ea2ba9eaddf83d33f781093617bf50f49b2bfe2f7173b113912e2e1775f40edfed8b3b0099b9e1c220dd103be6166210b01029feb24ed9e20614eddc3cebe41b0079a9a8c117b596c90288effd3796fbd0c7e8eab00609a64be3ad9597cdbf3a818c260cd938bdf232e4059ae35a2571a838887fc196912179486e046a62227a4caddce38cbbc37587bb9439ec637602b6818c5cbe3c71a7c4143960533dc74174bd315c8db227b69b55bb7fc30ba1d5213a752ec33925043cefbc1a62943ee5f34d5da01799e69094d732aef52f8e036980d0070e22e173c67c4bbcca61cc1eedbd6016516c592144819df13204dee",
        tag: "bf0540d34b20f761101bc608b02458f2",
    },
    // Source: Wycheproof (tcId=113)
    GcmVector {
        key: "4f62e56f7b15035f427849714beb97e6acf88371e1f69b388129bb447273d6b8",
        nonce: "137d5c98a92f6dcee4f29d7c",
        pt: "a147b716b86ac8dac7447d5ba60ee8a4191d2c64a3aa04276aee7bf7dc824962c09ace20a7e614cc9e177b5b11819b8f17008a9408e8cd8bb34b401be35368f492c17629b6467299bfd2ec4d9a7f17dea6f9ca084e871fb7fc78c2bf299b810522062726c5cae14b839722ecff499a2b3f082b6d1bfedb752f84a4e77459c9268d63199315363e9aaa39bea7fbbcc60a5eedc8a1a982ad6fa67c295b932eb3999047e0a99b3823032b6b3b7c4c553970afca50cb4e5ce859c25c598eb682005f17aec5526e26493208483679a23ccef6f7403a3f3055affd531a1cb7d183892dd577d526e8da8aa8b8b980a36e176b8d9293e785ac01bdd4dac8cf8dbdd82926f1e31408284fb3aa01f4414ac7aa7832d2ec02dd2db9b6b4b61d8c1cbb31dac7b6afa8d08b6877e439600c4a6fc07511877df2e9ce3a9538a726002a46c083d98124b185730f3b2aea2a01cb626be809f87b2ac100511c5b8fa0e9d40c9c999ea0aa87aad08cfb62c1ba869178be986156f7622d8c48ad80a552e9d08c36671ae232efefc8619c562e715f04ae52db2ad8e4a09e8c671b12289558117f9562d51beb59e29b10dd9eb232e8fcdb1cfdd14899acd693de14a7c076a4656386e23b06415b2c7a93b166cad1048bc605a49a79df3c03a3380de68a4f013e05e5283745d4078ebe308dc8881ced62ed571a93c69e8aae6e51f5e61e4ff75699aa32",
        aad: "",
        ct: "b194e6c8f83e09515d4ea95c00578fdaee8f9d35ad09a560ba81a51accc49416598516c747e16dbc5c44bfd5c790ba59b47a6f573a43b26cdbb240230b1dca00447770c4cf647df2a79eca3f4a8b2de08f9fbc4489c30f6bcfcd096f1aa4177fa281248e8e19e2ea7d1f049b7053947a3a67e946ebbed67466e009b63debceba54cc881e55e2d68f3f584380d6fb7b0e9a3fdbd709adac3a47d6f9a5fcaf03218e18cca5a7a0e340a774cd5c39d7031b63b5b5b896e1e705b4ded099c3c11150738b2107f61f1423fb72ed0a16070cd6f8a18ae90b167b707c23ddc85a1b6ff5a3ec5e654b1446c6eae787c31a94bc9ab5376dfea31bf8dfbdabce45c750111946e64c22d23c46d7ef644ca02c69205d59b1815a6a6e8b14fe7e2d8ad17fc75e656706b67f257523d517d9f8b83150a88359e56d6432859f8f90eaba70cf90f86995afc85c33992591536ba353ae14a6932dc96ad72687ac34c2d4d5c92e51da246f557785df1944d2c3c83536739b7d8475ba39c639df4ce69859c6ffb9e994545699a3a19d53979bfa34fdec856a9f12ac70bdeacf172721496d76d8073a76e8160d99f4b7466e05a8f006cb448d2af7ee308ca19440aaca08f34422da830e476269c829a2b5b64acea4f1143d1857cc2699ea3bf2e076b16e50a9071cf15352189edf278984102ebcc751d46510b816afafdb3fea37a7d49662ff090392",
        tag: "79e64c4c0e8bb3a214955584d2bc8b16",
    },
    // Source: Wycheproof (tcId=114)
    GcmVector {
        key: "6aada828b2273ffb81dc794a8629e305cb646f9d266002bd313427d384838767",
        nonce: "00dea4505cd5396f6ba408a5",
        pt: "1d99ee022f9576ed69af8a7f3945362ab0c4691a4d333a3f5f85cf8d7db7fb8a069b48998cf286ffa4615e87398c3c3c1295d5bee272bdeb5166470a8923f7b79dc92b2a97de34ba87db2907ac84fb23d38f2e1af835f737488fc04fac70432d3a0b02a472f851025803aac692273273e27be1dd9679a4d626997c363ba706a7db1f4cdc07fe3c67fbec0aa8619038e05607d95a5ddc4b403cd6dabc41790adb6cd76eaeac3491c3cd6a8787e0f29c042b4e2afe987674b9495ef55768c696bc6c3df1c1e9a7c0456f478a1a1cc4c3a9b0f2cd3b42db8d0b6aa36dfec3d2c08d1398eeb75db61ae902d2da5a1efac7904b8ae32af1ff942c99769504bb5c56f5819e4f899e8bbacfd4682d82f41e179a9ddf9a0820cc4316f252d1d35597aeda43ab870887e67aabe79f046b03a9a83588994058a07baedbbbf9c01d833732efac89ae8173f902e831d579d31e4a409cef5e494a27bb6367e84fc57642048e44d687ce73dd9e71384182b262d63a715698132f218fc2c3611ed0dbf814799866c8c43b4aa7c13b5a53f9a337627d76bb960f60fa891f0076a538c396500cefd2dd1e4e024f9d83275f9b2c0ce6df41bb6488398fc657dba0efdae0019dd31b03227edc5229aff60cd083c0f0b66675baaf91c3206819a0c985bc3283600e9e6d62c6fab2c6aefd69829c75063c54ad11269ac5ec563ecd870c2af4cde6cec43e",
        aad: "",
        ct: "75750a143887ad763c130a637e5d75fc7b53999e8a085a74a5c7e4e2658d03586f36dd67bdd0622992fc440822e63534391a435c934fa7fa19f5196695513ac812e778928a677af37a8bc36a19b7e3ab05e185429aa5e5e17cacdd8971e3c551db83c585324277843c1783771379280d1393eeb26e9e7ff7006d437b7cb0fe373b2dc3238d87badf9edd767ad7b4726a777b99cd1d11f1bc16098b1230a194bd9435caa0730276ebc0c44a923e3a14751e125aa7100cbd682202f9a71bf08e28ae36f55c6fce998a4c474dd5a5d55d25aef332c3b4640e20b222b7305dfc21f60e9f5dd97c1987120ba0b7b7e85ce810f378d401987b824679ffe45ccade89e5ed45176bab9d4a14c5a753d32e113a2aba5dfe65ac75918afed6cb2122cf24971fab932b64e104a8a01c755b4fb86afd49d0ce1a1909192551f579c3587d1a61ba5b0415cf90d572320af3b0c5d5d672d4207228e75322fffb621200fcb53d970f6a74e06bd90d8f9a1cf23c87c07deb14456dc21d84b8f6ca45b8c3af6d6d5c110488c919617c116c25baef4a7a0d47a4b247c94440176dd54a014d639a6139d83498a585b5687cea859dbb32b852690c4dcd23ae4058498ee751aec8aff3b0f1f0efd4bb50636d1182e111a6a98f95f2d55f8f4e75c1ae8a55e851c5095bcd9d1ad86fc79b0bf9ad2f58293a624c2504b30469f7ed1c645549d37177dfcd95",
        tag: "8fba48dab18a4beaddff24252e62083a",
    },
    // Source: Wycheproof (tcId=115)
    GcmVector {
        key: "afd579aa1accc682aca54e142aa69df09802f020b24a42c41db58f6997edc678",
        nonce: "9f79d1da957491069d774496",
        pt: "bafc6e865c48bd34b7f9329e35cfb286cd4dc31f8316171218bf0471dffd35a330a181697ca5178688dd87efe527924f90d1c78ba40de70952ff44c26efe2159e59358f3931573df9373a73b91ba9592e12140cc009feedd2595e5b6f066b5ef6de99d4c31552cecb0614f1dce990e46e7694382f3cf3ccfcd1ea62e563e5f0dc36cb5a84e0c0b3f1f8f3fa9100f487195ff2e3169ad08136aa8ad566548c9836aa00dbac74716c26e838c1486a0084d3dfd692585e2e5ae7c75caf0e7af60219f96116ae963b4a5899cb30a120daaca7833776692c25ad7c185e6a2d70ce03ff156cd25d76153539d6855773e21142f9ba0313562875f105a2b770a15b533fbf5110dafb69329982ab44ed1b9f321d7b79ae15a19d9f3bd4c504c24b23b812d514c19ae2a347cc18c12ce915a0bad7cc89a8720d4ba5ee0964fe05e4cc59a13f92c670b8655071e216f19ad05f4bbcca6dc7feeb188d6269c58065c98fcbbac183a9abb3811d80cb476544bd74b26991f3df987f0ed0ea6238659ac09a2250fecc0723ffc51647b74bdf454f26e11112c8bbd797f09a3be8251c6b5b319ed9537278cc1abedb32aa10840984b96e8636b289335846ae4fbd4a00f6600d98ebe25885c68d7043ce0dc5229d7e9bd51bea9b8fe0552f40688429c482629ced623f6074858147e73da3ff4ad2ae45c1a1c8a6c5b3b2c3d568a756608179f63b580fd",
        aad: "",
        ct: "cd48a6952868f7f7c8941652f6418b374db9afd4be179a948d336ba0d80438af895a21f268364fb1c5c6472f67bd4cb7e464068fe44377fb7cf4985b8428a068f5a1809498228fa8d8053650687afb9ebf3b19b43c38e56845e9350198ae0511efba7ea8bf8159a08f72e4227ec50da5b29dbb18fbf13cd22e13978efb04b02ba1a4b2b1ae171b612929d6772d958af38d3dfb2c11684a907d90b786b46ae494ed1c9da486cc7b54bd9cf2d34be34dd13013bd72e06fdad17ef143d5b857804de4a56409a35a4128fd752440fec02b9304cecce1bc6760d6fb0397bd1609ff303c9a0ea3bc5cc11482f083b6471f2e01d3d99ee23c35c37a62135d9cec9c69e053528448d813afda07fbd406ec74e0df2d1822bbf625392a2d91cc39d85c6de8ba43e5b7cf0ec2e4a0e18837f04b284d6ce6277bb91da9c0c3385bf0570181deeed3ce234e868b2c407a2a7d8d516b83cd86b844c23aaf3bece94a1f843007ccd8bc2859e0d64ba1614c2721bbb66a3a40e3f555a2b37e07fb15b116f69156a4260f1eb19d8140bc2ad3f9fd666ae35814e2fd1cfe178951f5e10cb85495e465773b4248bef9e7781e4a3fb6caf2f44180de42f4bff3772f3e87d8129db770c5e8a953e5a342c885ea1cd45a978792128ce420e63245ff0a1bb0730a7a506771e2a93874e3f1ee9ba9fc0af96a0d34d222d29aebd791416f399052adb295c3c43c",
        tag: "32b276fd0c1da7a823a5af074aecacb5",
    },
    // Source: Wycheproof (tcId=116)
    GcmVector {
        key: "0f112e59cdccd851c3b8e76c9f05a3b7c2e4feca5846afeb351c1cbcace82f04",
        nonce: "7147973339d86789a2c9a958",
        pt: "102e5804dda1fb5d656077edb15cadb5d0bdee8c",
        aad: "37128be45f0a7f329546e1492c3c9c2d2534d5b1f5147e49ab91221e7c3edea21bbe47bfe3619437ce3c61e6e946c504f348296918219e51bf2c5598589cff",
        ct: "618ac626ae0e8d06c2fd2fb66be253dc26ed6e38",
        tag: "d8d93ff975cb988f09174dcd439cb6a4",
    },
    // Source: Wycheproof (tcId=117)
    GcmVector {
        key: "2ce6b4c15f85fb2da5cc6c269491eef281980309181249ebf2832bd6d0732d0b",
        nonce: "c064fae9173b173fd6f11f34",
        pt: "f8a27a4baf00dc0555d222f2fa4fb42dc666ea3c",
        aad: "498d3075b09fed998280583d61bb36b6ce41f130063b80824d1586e143d349b126b16aa10fe57343ed223d6364ee602257fe313a7fc9bf9088f027795b8dc1d3",
        ct: "aed58d8a252f740dba4bf6d36773bd5b41234bba",
        tag: "01f93d7456aa184ebb49bea472b6d65d",
    },
    // Source: Wycheproof (tcId=118)
    GcmVector {
        key: "52350da5a572911ee0e0fcedb115af6f4570fbf9c74a11bc184444d6a621d60f",
        nonce: "d68ad045c1b9c2923cf5404c",
        pt: "4e6e6dad2c16cfc6e7cac03636a4a6d88bd6a13e",
        aad: "03a94b3841292d9bbf72f413c09167c54ee10537c049afe2bbcec43b18f3890b2fcdd3bb31e6d709274e199c0c4648eb3d8b38e0c1bf7f309443bef6937cde4123",
        ct: "c7764411be13cfeaaece761bd3bb13552f088048",
        tag: "bcc2544e79f34ea1076a12b76441d6fa",
    },
    // Source: Wycheproof (tcId=119)
    GcmVector {
        key: "d058304c0ba039b2e2d08661fd8f6db88779bd5ce580eb766c1d6ab34b94ee94",
        nonce: "3c553397fafda0eb06a59f23",
        pt: "0a064cd5e49845c4efb60fb343dc03faffa36c49",
        aad: "cfb1fe1c47e2450109eaed4e1aac9431aa5db1e3b7eeacad3ebc9e8e1f3e0a823f757f619761e61ad05af8cef83104890940cd592137eb7ba5879b95759c8be1525f9a01fc01582d93a2a841336a104d169968c274b5a8c30883b4bd621725f69079bb94a174a3c94db62f2ae746d03200f01c19aaa8a3b89e78b99a62f76f",
        ct: "a7d84ff71dc713161359b757af42c74dddbf53ce",
        tag: "736e48a2b7792acc599baa651629a203",
    },
    // Source: Wycheproof (tcId=120)
    GcmVector {
        key: "44c8d0cdb8f7e736cfd997c872a5d9c5ef30afbe44b6566606b90aa5e3e8b797",
        nonce: "6f39afba021e4c36eb92962e",
        pt: "2e6f40f9d3725836ac0c858177938fd67be19432",
        aad: "98d1ca1788cbeb300ea5c6b1eec95eb2347177201400913d45225622b6273eec8a74c3f12c8d5248dabee586229786ff192c4df0c79547f7ad6a92d78d9f8952758635783add2a5977d386e0aef76482211d2c3ae98de4baadb3f8b35b510464755dc75ceb2bf25b233317523f399a6c507db214f085fa2818f0d3702b10952b",
        ct: "b42428f8094ef7e65c9e8c45ef3e95c28ce07d72",
        tag: "32b25dfbb896d0f9d79c823bdd8e5d06",
    },
    // Source: Wycheproof (tcId=121)
    GcmVector {
        key: "e27e718e4b66c91e221f2a3df9da0013f7e14340006eca50dc30c4cc2ddeb679",
        nonce: "b46fed185e8b33215dd474dd",
        pt: "e39aeaf1d214f78915601fee9a3527d777674651",
        aad: "2d2b6247f9c342f8d0432ce0715749d0bac0e2e3f28b785be8dc84b3a0e57a161afde34227277512204ffa4bceb6e0a4d021031b765540f7f613045f74e7e6e4977c04b78b5d3f8d4e420a9748c12d1f9aa5e03a27749be2785dd555a8cf0182c0826f2d60eed3c4059adf8872f3c4d81a963592472965cc0c66102167e4cb1ca2",
        ct: "750232115a5edea7b249a22c0cdae17f725d6f99",
        tag: "4a72d8c30fc7e0f1806d9a817adae14a",
    },
    // Source: Wycheproof (tcId=122)
    GcmVector {
        key: "fc1bfd0b58515c4e7906e2052596bb92de8c879806af47a4c726ff08c9ba47cc",
        nonce: "f3da3be574337b8f8c052866",
        pt: "9adfced8e23f7897b66efcc3468d63b87da79a24",
        aad: "d26f7ff887725228f3109924ed9eaeaa8c103cfcaac1d6e3874d11afd8424fd030fea80547212fe7c8ac9f4ecbe304b62e5bb206ac3a8318a819b9701f494aefd22e84d227922102f5130f0685e88e25115c3ab9e8bb290c0df0715c4adb00a2ecc9bab5bbcc49cec60305a5b04f646b1d0f951673cf1eb4742c1a52beb2cd2f43a2e413e4a9f5679123b4d59f2ae14c27ee84e970cafcbb5a0736ad2636833cb644c9f2fb61a4a09fad511f4c1781c5685f94814d242c5e3eb4abe165732ab0258a2461c56d452ef1cf48b4ff0f331b91c2c71ce1c03877552837a12dfe75f78bf1cd615b3b2b864fd9503a5f5bea652870bce4cad5c726f1c512dae7f5f8",
        ct: "1875d3d76930b58361103d64220591feaad5c9a2",
        tag: "223099bb16c30cba134e639ed95615b7",
    },
    // Source: Wycheproof (tcId=123)
    GcmVector {
        key: "7ec20e38aa1b1f018d79903fc1cf6e260cec3733a19ad9e30f60b54e2ea6ebcc",
        nonce: "5ccd9cdcf97ac61364687bbb",
        pt: "bab28e0987509b1d6f9cf3aa90030795f125ee44",
        aad: "d9d2ee145b5c31a17dce932538c7e45da1c82abb80b0553251e442dbc5af9c126d3a76a24767c39b229bec8976a0df89fa70ea9ad872aa36d6b8b09aaa54698e7f29c2c2d12efb0b301cfb97076473dfa7ec030350e26839fbb7e1612dad93ff08e1119168c5fca56816c62b042f06d89e5a95da6a615e13ba4cad9f942534c539520d00509d0d4ac6d80c59e769d7e1aa7e12987ee05fb6a19b383c3348df6cbdcff604ef218338910a8e275d9a62b802cb07ec9249c9635e2437f8339dff3e21f79e9eb2acc2bbbadd520a84c58f0ddaaf8c32496d173b6b8c0c274352d40d47bfbd93069abdcc3d21c2cd330a8c16847f0e5299beb6a2d33be746de5c71f2",
        ct: "ce4c58d3c7354d2d27e3bb41a62e5941fb1e39f3",
        tag: "e177391d5e2cefa2f7d35e33a76566aa",
    },
    // Source: Wycheproof (tcId=124)
    GcmVector {
        key: "e40003d6e08ab80b4bfc8400ef112945a901ec64a1b6536ca92665090d608bc4",
        nonce: "9f095dafe6f6e0fbafbbe02e",
        pt: "38c3f44bc5765de1f3d1c3684cd09cddefaf298d",
        aad: "422d5efcffe364905984533f0a579d80b18bda7b29e6e46498effba53c350112c0bbb8dc4ce03bb0c69e1d0baa19f0637108aa4a16b09a281f232839d87b6d0e42be1baa7c67f1be970ea169d3960b9fe0a61f11cd2eb7398c19e641feb43f778e257a397063db5b3a6707e9db62387054f9f9d44f143583e63edad45a00251e5173d7505f22a8bce232e56c2c276a58033ae30d5dbf4e35a862e42af573be38c6406d9b4c7acbf275fe36c0ecf2c4642898a30e6146fac992a16405f98312126b7a3722f5dfb7dd4e4911c1426b2e01d04e9be6db3771100f7d7d4282e4ea585f3646241e807ca64f06a7fa9b7003d710b801d66f517d2d5ebd740872deba13d0",
        ct: "d4a79f729487935950ec032e690ab8fe25c4158e",
        tag: "876d2f334f47968b10c103859d436db8",
    },
    // Source: Wycheproof (tcId=125)
    GcmVector {
        key: "820bb5eb3707e713d5fcfe3c98bb1ba733540ddf44b172746bb950957254adb5",
        nonce: "f2b947eae4311254417c5928",
        pt: "81c37b34c4369ecc1a9cdd6f1557133e59249165",
        aad: "f76c06fe9dfa7fffddae7d545977f1944bdb8e48bb8740ff1a9a90c260e1264fdbfa328ed8f183e672892a6d3464c176adab5da8ab3af7c08b71ad135d7b42c3ebd893938f82cb9d200bb50c26e823af951149407bcc05f17fbe8ec275db96a9c7aa230f1347bcf10202d5cb7fb16076f6a78cd620fdd67a9be58f6992e619a8314cb40446b654d1c01c9cc6a92e44a77b015f2cefb9e5284082951bd98ee7e834adf39306bdd4288296c276e63b0dba7b7269c63e0e77f3df0debe8fe36454ed7ab332db77d2d9d7e1832f36e13ac6c88e383dc8533bc624a27ae378758742a63e39d54fec827b19c63c692cdbc6a498ce80c5c112d461cbed6c93a458573c765c759776e7b8e3430ca389991996f895ee16fe538f2de3a902f8423138f05e87e01c1adf2232ce9eff100b39452565c10125b3a852183f8026b1cb8281e9e2e6a0fbdde64d0f4c2984a72f1ae2bfbb409c9de9ad2244860996e1053cc8cdd70511bb265f20561a0337de4891fbf293f705fe040f187ba43bf13fb5e02031f8edce5db10ef5d411a448ce0903dde943d2e199f0e4af2ad3ab2a534f0d6418acbc5ea9340356e11036bf6dec306419177630d36b41a0e646388f6010227a323f9570f43f2f14a8b9fa346ad0459c0c28ce6ca2eed98983bd08db82bfd0945bd4c94bd82a4046876d7a3844a4fb9365284b1511b6fb36a2703abc9b03a6244bf",
        ct: "8d529d8a4f0d7ec4e41d8d361663df53c479ac34",
        tag: "d509e3e1eccfe38f7c63f9a55f42946a",
    },
    // Source: Wycheproof (tcId=126)
    GcmVector {
        key: "65e18f70f168abaf388104c9b37a9686aebc7743f0e66b84b7c7cc0e3600f655",
        nonce: "8d564420fcb9a98e7e07475c",
        pt: "12d3cc4473970296d2918818fdcf1a570d2d4821",
        aad: "016dde724536eee27187907263e4a62f3b637eaa8ab6f86d0343f66f7f73c6f8c3416cf253532454c045557ed7a371c2d6b8e19e0101e1109cd7227dc5390545ff24484031957749514379a77a33df0fd129f80e9869747b6589fd29a6935aa37b00e2abbbae2b67904726e9fe22143080af18821ff10c5217e845cd6e0ef2513c1d82c14f9d3933f3fd5c6364075aebef6c0f5c97fa343aa192ba8c526b7ad4c71c4c19ad2d5ae05b07176a5e66d486889a2e8f9ef80b9c0680cf887f60137f6266ec335a5f1d74dc41dec1653a96d61b75f4b569b9328f6b2fb40391704f66e058e92dfc15d77599018d74907a9bb8870c5c446e81fa7a764a549f6a417326b52fbbe4f5885e6455be2890c3a8b97a9fd0c92c085edfaf6a4f28dfec0243aa79a71d123282d4e9a0b3497ad569db869e56638e271f1205a52fc38cb74767e4bb2f37bd437083e994395e98454c04092d292c681ade9e398589df6cbf9b3196d12c8153740647af018cab5f9bf3e3db7deea221c73f377b96d368ff8d9ffecb8f44d50b59fafc90f655ec9271c9c1d032cfb0f23720d01981c26296536e66cdb8c390ad1bca90e6b2711170665ad52aaa188f87ca96888d3d932e6c3bf32891cd746308b0d6345ed8cf7c1ad88442326a3892e60afd5c86a2d062a461d8896446154e9148aad5b122437e26a52ba1b620d085af628af5ada9fff664d4a9a230",
        ct: "2844b68b9356049934b031b0d6de55b50fab0f46",
        tag: "387bc3a46530bdf24b1cfa67899369ea",
    },
    // Source: Wycheproof (tcId=127)
    GcmVector {
        key: "b15ab816ba505ec42b528066d9119b4b2ee38159ce54a26bc5d661127e05222c",
        nonce: "75e3c608a39367dc4aa748d0",
        pt: "8b2a6a9604b25d1670b7d869c649a05399b8ada5",
        aad: "005931a2d5c5bcedc716c3f246e21b3a46d2a6b1ce73644653e0cf277efa492f12fb2b83f70bae8737d53cd76254dabca8422d4ff9396c265d57e4fd3d0cd1c38198e229637c7fbfff468fcdb04ca12101865c08bbf55689e1299c5e7a430296c47a874d9956557b2cb32fd3f8073f85fefb6d2005c5d3329e40dcb957f5b01d7f1582ea359b947d5669da8003c009f8ecbfbf094fb8155cf89251ee4a91a43a96e3f6d302e15753dd48dd5e3b87e093021059ec323d38d3ee72290521eefd54cf708aa9e81869b756c3fc3c9a60e12226ac643bf7a91951e5509159b1e298bbfe88fd8ee659cac98c904f68c928403894fc89df100d6f30fd1ce20666815929b6eee39ece510eb53567e35cbe49dcec0f1b80fee861ed0af1cc759d477f306a5e1273e64c7e33554d11d79632006b420e7c71d36fece18d75a8b5773171ed071c26664fc0113277e3356ab30db05ac62ea5b975e36413572dd39e5c22d5c42bc82ab0ab85b54fbfaa527d1344dc3dfb18b941b05bcc5b47d25e18ef936f3918ed87cbf5dfa67989a038e2f747345c4b8d27b101c944f0f1d6fe21cd1a653c17530f9a893d7fd48afafcf12bf005fe044a000e8deaf09bed39ba62784bd5b88ace564806a9b5e0bf40f9f655fdd5bdc4bf568c5abb4b84ec61a85f0038b4f4cc3e75c3b3f99e62b99292d510f690c07c18af41b765fe5a1ee9484cf04c69f3f49c",
        ct: "371fa70af8a198cb43ddd545e74b806246f7e932",
        tag: "014a0179b81691d09011dcea5739551d",
    },
    // Source: Wycheproof (tcId=128)
    GcmVector {
        key: "00112233445566778899aabbccddeeff102132435465768798a9bacbdcedfe0f",
        nonce: "000000000000000000000000",
        pt: "561008fa07a68f5c61285cd013464eaf",
        aad: "",
        ct: "23293e9b07ca7d1b0cae7cc489a973b3",
        tag: "ffffffffffffffffffffffffffffffff",
    },
    // Source: Wycheproof (tcId=129)
    GcmVector {
        key: "00112233445566778899aabbccddeeff102132435465768798a9bacbdcedfe0f",
        nonce: "ffffffffffffffffffffffff",
        pt: "c6152244cea1978d3e0bc274cf8c0b3b",
        aad: "",
        ct: "7cb6fc7c6abc009efe9551a99f36a421",
        tag: "00000000000000000000000000000000",
    },
    // Source: pyca/cryptography (Count=0)
    GcmVector {
        key: "b52c505a37d78eda5dd34f20c22540ea1b58963cf8e5bf8ffa85f9f2492505b4",
        nonce: "516c33929df5a3284ff463d7",
        pt: "",
        aad: "",
        ct: "",
        tag: "bdc1ac884d332457a1d2664f168c76f0",
    },
    // Source: pyca/cryptography (Count=1)
    GcmVector {
        key: "5fe0861cdc2690ce69b3658c7f26f8458eec1c9243c5ba0845305d897e96ca0f",
        nonce: "770ac1a5a3d476d5d96944a1",
        pt: "",
        aad: "",
        ct: "",
        tag: "196d691e1047093ca4b3d2ef4baba216",
    },
    // Source: pyca/cryptography (Count=2)
    GcmVector {
        key: "7620b79b17b21b06d97019aa70e1ca105e1c03d2a0cf8b20b5a0ce5c3903e548",
        nonce: "60f56eb7a4b38d4f03395511",
        pt: "",
        aad: "",
        ct: "",
        tag: "f570c38202d94564bab39f75617bc87a",
    },
    // Source: pyca/cryptography (Count=3)
    GcmVector {
        key: "7e2db00321189476d144c5f27e787087302a48b5f7786cd91e93641628c2328b",
        nonce: "ea9d525bf01de7b2234b606a",
        pt: "",
        aad: "",
        ct: "",
        tag: "db9df5f14f6c9f2ae81fd421412ddbbb",
    },
    // Source: pyca/cryptography (Count=4)
    GcmVector {
        key: "a23dfb84b5976b46b1830d93bcf61941cae5e409e4f5551dc684bdcef9876480",
        nonce: "5aa345908048de10a2bd3d32",
        pt: "",
        aad: "",
        ct: "",
        tag: "f28217649230bd7a40a9a4ddabc67c43",
    },
    // Source: pyca/cryptography (Count=5)
    GcmVector {
        key: "dfe928f86430b78add7bb7696023e6153d76977e56103b180253490affb9431c",
        nonce: "1dd0785af9f58979a10bd62d",
        pt: "",
        aad: "",
        ct: "",
        tag: "a55eb09e9edef58d9f671d72207f8b3c",
    },
    // Source: pyca/cryptography (Count=6)
    GcmVector {
        key: "34048db81591ee68224956bd6989e1630fcf068d7ff726ae81e5b29f548cfcfb",
        nonce: "1621d34cff2a5b250c7b76fc",
        pt: "",
        aad: "",
        ct: "",
        tag: "4992ec3d57cccfa58fd8916c59b70b11",
    },
    // Source: pyca/cryptography (Count=7)
    GcmVector {
        key: "a1114f8749c72b8cef62e7503f1ad921d33eeede32b0b5b8e0d6807aa233d0ad",
        nonce: "a190ed3ff2e238be56f90bd6",
        pt: "",
        aad: "",
        ct: "",
        tag: "c8464d95d540fb191156fbbc1608842a",
    },
    // Source: pyca/cryptography (Count=8)
    GcmVector {
        key: "ddbb99dc3102d31102c0e14b238518605766c5b23d9bea52c7c5a771042c85a0",
        nonce: "95d15ed75c6a109aac1b1d86",
        pt: "",
        aad: "",
        ct: "",
        tag: "813d1da3775cacd78e96d86f036cff96",
    },
    // Source: pyca/cryptography (Count=9)
    GcmVector {
        key: "1faa506b8f13a2e6660af78d92915adf333658f748f4e48fa20135a29e9abe5f",
        nonce: "e50f278d3662c99d750f60d3",
        pt: "",
        aad: "",
        ct: "",
        tag: "aec7ece66b7344afd6f6cc7419cf6027",
    },
    // Source: pyca/cryptography (Count=10)
    GcmVector {
        key: "f30b5942faf57d4c13e7a82495aedf1b4e603539b2e1599317cc6e53225a2493",
        nonce: "336c388e18e6abf92bb739a9",
        pt: "",
        aad: "",
        ct: "",
        tag: "ddaf8ef4cb2f8a6d401f3be5ff0baf6a",
    },
    // Source: pyca/cryptography (Count=11)
    GcmVector {
        key: "daf4d9c12c5d29fc3fa936532c96196e56ae842e47063a4b29bfff2a35ed9280",
        nonce: "5381f21197e093b96cdac4fa",
        pt: "",
        aad: "",
        ct: "",
        tag: "7f1832c7f7cd7812a004b79c3d399473",
    },
    // Source: pyca/cryptography (Count=12)
    GcmVector {
        key: "6b524754149c81401d29a4b8a6f4a47833372806b2d4083ff17f2db3bfc17bca",
        nonce: "ac7d3d618ab690555ec24408",
        pt: "",
        aad: "",
        ct: "",
        tag: "db07a885e2bd39da74116d06c316a5c9",
    },
    // Source: pyca/cryptography (Count=13)
    GcmVector {
        key: "cff083303ff40a1f66c4aed1ac7f50628fe7e9311f5d037ebf49f4a4b9f0223f",
        nonce: "45d46e1baadcfbc8f0e922ff",
        pt: "",
        aad: "",
        ct: "",
        tag: "1687c6d459ea481bf88e4b2263227906",
    },
    // Source: pyca/cryptography (Count=14)
    GcmVector {
        key: "3954f60cddbb39d2d8b058adf545d5b82490c8ae9283afa5278689041d415a3a",
        nonce: "8fb3d98ef24fba03746ac84f",
        pt: "",
        aad: "",
        ct: "",
        tag: "7fb130855dfe7a373313361f33f55237",
    },
    // Source: pyca/cryptography (Count=1)
    GcmVector {
        key: "4457ff33683cca6ca493878bdc00373893a9763412eef8cddb54f91318e0da88",
        nonce: "699d1f29d7b8c55300bb1fd2",
        pt: "",
        aad: "6749daeea367d0e9809e2dc2f309e6e3",
        ct: "",
        tag: "d60c74d2517fde4a74e0cd4709ed43a9",
    },
    // Source: pyca/cryptography (Count=2)
    GcmVector {
        key: "4d01c96ef9d98d4fb4e9b61be5efa772c9788545b3eac39eb1cacb997a5f0792",
        nonce: "32124a4d9e576aea2589f238",
        pt: "",
        aad: "d72bad0c38495eda50d55811945ee205",
        ct: "",
        tag: "6d6397c9e2030f5b8053bfe510f3f2cf",
    },
    // Source: pyca/cryptography (Count=3)
    GcmVector {
        key: "8378193a4ce64180814bd60591d1054a04dbc4da02afde453799cd6888ee0c6c",
        nonce: "bd8b4e352c7f69878a475435",
        pt: "",
        aad: "1c6b343c4d045cbba562bae3e5ff1b18",
        ct: "",
        tag: "0833967a6a53ba24e75c0372a6a17bda",
    },
    // Source: pyca/cryptography (Count=4)
    GcmVector {
        key: "22fc82db5b606998ad45099b7978b5b4f9dd4ea6017e57370ac56141caaabd12",
        nonce: "880d05c5ee599e5f151e302f",
        pt: "",
        aad: "3e3eb5747e390f7bc80e748233484ffc",
        ct: "",
        tag: "2e122a478e64463286f8b489dcdd09c8",
    },
    // Source: pyca/cryptography (Count=5)
    GcmVector {
        key: "fc00960ddd698d35728c5ac607596b51b3f89741d14c25b8badac91976120d99",
        nonce: "a424a32a237f0df530f05e30",
        pt: "",
        aad: "cfb7e05e3157f0c90549d5c786506311",
        ct: "",
        tag: "dcdcb9e4004b852a0da12bdf255b4ddd",
    },
    // Source: pyca/cryptography (Count=6)
    GcmVector {
        key: "69749943092f5605bf971e185c191c618261b2c7cc1693cda1080ca2fd8d5111",
        nonce: "bd0d62c02ee682069bd1e128",
        pt: "",
        aad: "6967dce878f03b643bf5cdba596a7af3",
        ct: "",
        tag: "378f796ae543e1b29115cc18acd193f4",
    },
    // Source: pyca/cryptography (Count=7)
    GcmVector {
        key: "fc4875db84819834b1cb43828d2f0ae3473aa380111c2737e82a9ab11fea1f19",
        nonce: "da6a684d3ff63a2d109decd6",
        pt: "",
        aad: "91b6fa2ab4de44282ffc86c8cde6e7f5",
        ct: "",
        tag: "504e81d2e7877e4dad6f31cdeb07bdbd",
    },
    // Source: pyca/cryptography (Count=8)
    GcmVector {
        key: "9f9fe7d2a26dcf59d684f1c0945b5ffafe0a4746845ed317d35f3ed76c93044d",
        nonce: "13b59971cd4dd36b19ac7104",
        pt: "",
        aad: "190a6934f45f89c90067c2f62e04c53b",
        ct: "",
        tag: "4f636a294bfbf51fc0e131d694d5c222",
    },
    // Source: pyca/cryptography (Count=9)
    GcmVector {
        key: "ab9155d7d81ba6f33193695cf4566a9b6e97a3e409f57159ae6ca49655cca071",
        nonce: "26a9f8d665d163ddb92d035d",
        pt: "",
        aad: "4a203ac26b951a1f673c6605653ec02d",
        ct: "",
        tag: "437ea77a3879f010691e288d6269a996",
    },
    // Source: pyca/cryptography (Count=10)
    GcmVector {
        key: "0f1c62dd80b4a6d09ee9d787b1b04327aa361529ffa3407560414ac47b7ef7bc",
        nonce: "c87613a3b70d2a048f32cb9a",
        pt: "",
        aad: "8f23d404be2d9e888d219f1b40aa29e8",
        ct: "",
        tag: "36d8a309acbb8716c9c08c7f5de4911e",
    },
    // Source: pyca/cryptography (Count=11)
    GcmVector {
        key: "f3e954a38956df890255f01709e457b33f4bfe7ecb36d0ee50f2500471eebcde",
        nonce: "9799abd3c52110c704b0f36a",
        pt: "",
        aad: "ddb70173f44157755b6c9b7058f40cb7",
        ct: "",
        tag: "b323ae3abcb415c7f420876c980f4858",
    },
    // Source: pyca/cryptography (Count=12)
    GcmVector {
        key: "0625316534fbd82fe8fdea50fa573c462022c42f79e8b21360e5a6dce66dde28",
        nonce: "da64a674907cd6cf248f5fbb",
        pt: "",
        aad: "f24d48e04f5a0d987ba7c745b73b0364",
        ct: "",
        tag: "df360b810f27e794673a8bb2dc0d68b0",
    },
    // Source: pyca/cryptography (Count=13)
    GcmVector {
        key: "28f045ac7c4fe5d4b01a9dcd5f1ad3efff1c4f170fc8ab8758d97292868d5828",
        nonce: "5d85de95b0bdc44514143919",
        pt: "",
        aad: "601d2158f17ab3c7b4dcb6950fbdcdde",
        ct: "",
        tag: "42c3f527418cf2c3f5d5010ccba8f271",
    },
    // Source: pyca/cryptography (Count=14)
    GcmVector {
        key: "19310eed5f5f44eb47075c105eb31e36bbfd1310f741b9baa66a81138d357242",
        nonce: "a1247120138fa4f0e96c992c",
        pt: "",
        aad: "29d746414333e0f72b4c3f44ec6bfe42",
        ct: "",
        tag: "d5997e2f956df3fa2c2388e20f30c480",
    },
    // Source: pyca/cryptography (Count=0)
    GcmVector {
        key: "886cff5f3e6b8d0e1ad0a38fcdb26de97e8acbe79f6bed66959a598fa5047d65",
        nonce: "3a8efa1cd74bbab5448f9945",
        pt: "",
        aad: "519fee519d25c7a304d6c6aa1897ee1eb8c59655",
        ct: "",
        tag: "f6d47505ec96c98a42dc3ae719877b87",
    },
    // Source: pyca/cryptography (Count=1)
    GcmVector {
        key: "6937a57d35fe6dc3fc420b123bccdce874bd4c18f2e7c01ce2faf33d3944fd9d",
        nonce: "a87247797b758467b96310f3",
        pt: "",
        aad: "ead961939a33dd578f8e93db8b28a1c85362905f",
        ct: "",
        tag: "599de3ecf22cb867f03f7f6d9fd7428a",
    },
    // Source: pyca/cryptography (Count=2)
    GcmVector {
        key: "e65a331776c9dcdf5eba6c59e05ec079d97473bcdce84daf836be323456263a0",
        nonce: "ca731f768da01d02eb8e727e",
        pt: "",
        aad: "d7274586517bf1d8da866f4a47ad0bcf2948a862",
        ct: "",
        tag: "a8abe7a8085f25130a7206d37a8aaf6d",
    },
    // Source: pyca/cryptography (Count=3)
    GcmVector {
        key: "77bb1b6ef898683c981b2fc899319ffbb6000edca22566b634db3a3c804059e5",
        nonce: "354a19283769b3b991b05a4c",
        pt: "",
        aad: "b5566251a8a8bec212dc08113229ff8590168800",
        ct: "",
        tag: "e5c2dccf8fc7f296cac95d7071cb8d7d",
    },
    // Source: pyca/cryptography (Count=4)
    GcmVector {
        key: "2a43308d520a59ed51e47a3a915e1dbf20a91f0886506e481ad3de65d50975b4",
        nonce: "bcbf99733d8ec90cb23e6ce6",
        pt: "",
        aad: "eb88288729289d26fe0e757a99ad8eec96106053",
        ct: "",
        tag: "01b0196933aa49123eab4e1571250383",
    },
    // Source: pyca/cryptography (Count=5)
    GcmVector {
        key: "2379b35f85102db4e7aecc52b705bc695d4768d412e2d7bebe999236783972ff",
        nonce: "918998c4801037b1cd102faa",
        pt: "",
        aad: "b3722309e0f066225e8d1659084ebb07a93b435d",
        ct: "",
        tag: "dfb18aee99d1f67f5748d4b4843cb649",
    },
    // Source: pyca/cryptography (Count=6)
    GcmVector {
        key: "98b3cb7537167e6d14a2a8b2310fe94b715c729fdf85216568150b556d0797ba",
        nonce: "bca5e2e5a6b30f18d263c6b2",
        pt: "",
        aad: "260d3d72db70d677a4e3e1f3e11431217a2e4713",
        ct: "",
        tag: "d6b7560f8ac2f0a90bad42a6a07204bc",
    },
    // Source: pyca/cryptography (Count=7)
    GcmVector {
        key: "30341ae0f199b10a15175d00913d5029526ab7f761c0b936a7dd5f1b1583429d",
        nonce: "dbe109a8ce5f7b241e99f7af",
        pt: "",
        aad: "fe4bdee5ca9c4806fa024715fbf66ab845285fa7",
        ct: "",
        tag: "ae91daed658e26c0d126575147af9899",
    },
    // Source: pyca/cryptography (Count=8)
    GcmVector {
        key: "8232b6a1d2e367e9ce1ea8d42fcfc83a4bc8bdec465c6ba326e353ad9255f207",
        nonce: "cd2fb5ff9cf0f39868ad8685",
        pt: "",
        aad: "02418b3dde54924a9628de06004c0882ae4ec3bb",
        ct: "",
        tag: "d5308f63708675ced19b2710afd2db49",
    },
    // Source: pyca/cryptography (Count=9)
    GcmVector {
        key: "f9a132a50a508145ffd8294e68944ea436ce0f9a97e181f5e0d6c5d272311fc1",
        nonce: "892991b54e94b9d57442ccaf",
        pt: "",
        aad: "4e0fbd3799da250fa27911b7e68d7623bfe60a53",
        ct: "",
        tag: "89881d5f786e6d53e0d19c3b4e6887d8",
    },
    // Source: pyca/cryptography (Count=10)
    GcmVector {
        key: "0e3746e5064633ea9311b2b8427c536af92717de20eeb6260db1333c3d8a8114",
        nonce: "f84c3a1c94533f7f25cec0ac",
        pt: "",
        aad: "8c0d41e6135338c8d3e63e2a5fa0a9667ec9a580",
        ct: "",
        tag: "479ccfe9241de2c474f2edebbb385c09",
    },
    // Source: pyca/cryptography (Count=11)
    GcmVector {
        key: "b997e9b0746abaaed6e64b63bdf64882526ad92e24a2f5649df055c9ec0f1daa",
        nonce: "f141d8d71b033755022f0a7d",
        pt: "",
        aad: "681d6583f527b1a92f66caae9b1d4d028e2e631e",
        ct: "",
        tag: "b30442a6395ec13246c48b21ffc65509",
    },
    // Source: pyca/cryptography (Count=12)
    GcmVector {
        key: "87660ec1700d4e9f88a323a49f0b871e6aaf434a2d8448d04d4a22f6561028e0",
        nonce: "2a07b42593cd24f0a6fe406c",
        pt: "",
        aad: "1dd239b57185b7e457ced73ebba043057f049edd",
        ct: "",
        tag: "df7a501049b37a534098cb45cb9c21b7",
    },
    // Source: pyca/cryptography (Count=13)
    GcmVector {
        key: "ea4792e1f1717b77a00de4d109e627549b165c82af35f33ca7e1a6b8ed62f14f",
        nonce: "7453cc8b46fe4b93bcc48381",
        pt: "",
        aad: "46d98970a636e7cd7b76fc362ae88298436f834f",
        ct: "",
        tag: "518dbacd36be6fba5c12871678a55516",
    },
    // Source: pyca/cryptography (Count=14)
    GcmVector {
        key: "34892cdd1d48ca166f7ba73182cb97336c2c754ac160a3e37183d6fb5078cec3",
        nonce: "ed3198c5861b78c71a6a4eec",
        pt: "",
        aad: "a6fa6d0dd1e0b95b4609951bbbe714de0ae0ccfa",
        ct: "",
        tag: "c6387795096b348ecf1d1f6caaa3c813",
    },
    // Source: pyca/cryptography (Count=0)
    GcmVector {
        key: "f4069bb739d07d0cafdcbc609ca01597f985c43db63bbaaa0debbb04d384e49c",
        nonce: "d25ff30fdc3d464fe173e805",
        pt: "",
        aad: "3e1449c4837f0892f9d55127c75c4b25d69be334baf5f19394d2d8bb460cbf2120e14736d0f634aa792feca20e455f11",
        ct: "",
        tag: "805ec2931c2181e5bfb74fa0a975f0cf",
    },
    // Source: pyca/cryptography (Count=1)
    GcmVector {
        key: "62189dcc4beb97462d6c0927d8a270d39a1b07d72d0ad28840badd4f68cf9c8b",
        nonce: "859fda5247c888823a4b8032",
        pt: "",
        aad: "b28d1621ee110f4c9d709fad764bba2dd6d291bc003748faac6d901937120d41c1b7ce67633763e99e05c71363fceca8",
        ct: "",
        tag: "27330907d0002880bbb4c1a1d23c0be2",
    },
    // Source: pyca/cryptography (Count=2)
    GcmVector {
        key: "59012d85a1b90aeb0359e6384c9991e7be219319f5b891c92c384ade2f371816",
        nonce: "3c9cde00c23912cff9689c7c",
        pt: "",
        aad: "e5daf473a470860b55210a483c0d1a978d8add843c2c097f73a3cda49ac4a614c8e887d94e6692309d2ed97ebe1eaf5d",
        ct: "",
        tag: "048239e4e5c2c8b33890a7c950cda852",
    },
    // Source: pyca/cryptography (Count=3)
    GcmVector {
        key: "4be09b408ad68b890f94be5efa7fe9c917362712a3480c57cd3844935f35acb7",
        nonce: "8f350bd3b8eea173fc7370bc",
        pt: "",
        aad: "2819d65aec942198ca97d4435efd9dd4d4393b96cf5ba44f09bce4ba135fc8636e8275dcb515414b8befd32f91fc4822",
        ct: "",
        tag: "a133cb7a7d0471dbac61fb41589a2efe",
    },
    // Source: pyca/cryptography (Count=4)
    GcmVector {
        key: "13cb965a4d9d1a36efad9f6ca1ba76386a5bb160d80b0917277102357ac7afc8",
        nonce: "f313adec42a66d13c3958180",
        pt: "",
        aad: "717b48358898e5ccfea4289049adcc1bb0db3b3ebd1767ac24fb2b7d37dc80ea2316c17f14fb51b5e18cd5bb09afe414",
        ct: "",
        tag: "81b4ef7a84dc4a0b1fddbefe37f53852",
    },
    // Source: pyca/cryptography (Count=5)
    GcmVector {
        key: "d27f1bebbbdef0edca393a6261b0338abbc491262eab0737f55246458f6668cc",
        nonce: "fc062f857886e278f3a567d2",
        pt: "",
        aad: "2bae92dea64aa99189de8ea4c046745306002e02cfb46a41444ce8bfcc329bd4205963d9ab5357b026a4a34b1a861771",
        ct: "",
        tag: "5c5a6c4613f1e522596330d45f243fdd",
    },
    // Source: pyca/cryptography (Count=6)
    GcmVector {
        key: "7b4d19cd3569f74c7b5df61ab78379ee6bfa15105d21b10bf6096699539006d0",
        nonce: "fbed5695c4a739eded97b1e3",
        pt: "",
        aad: "c6f2e5d663bfaf668d014550ef2e66bf89978799a785f1f2c79a2cb3eb3f2fd4076207d5f7e1c284b4af5cffc4e46198",
        ct: "",
        tag: "7101b434fb90c7f95b9b7a0deeeb5c81",
    },
    // Source: pyca/cryptography (Count=7)
    GcmVector {
        key: "d3431488d8f048590bd76ec66e71421ef09f655d7cf8043bf32f75b4b2e7efcc",
        nonce: "cc766e98b40a81519fa46392",
        pt: "",
        aad: "93320179fdb40cbc1ccf00b872a3b4a5f6c70b56e43a84fcac5eb454a0a19a747d452042611bf3bbaafd925e806ffe8e",
        ct: "",
        tag: "3afcc336ce8b7191eab04ad679163c2a",
    },
    // Source: pyca/cryptography (Count=8)
    GcmVector {
        key: "a440948c0378561c3956813c031f81573208c7ffa815114ef2eee1eb642e74c6",
        nonce: "c1f4ffe54b8680832eed8819",
        pt: "",
        aad: "253438f132b18e8483074561898c5652b43a82cc941e8b4ae37e792a8ed6ec5ce2bcec9f1ffcf4216e46696307bb774a",
        ct: "",
        tag: "129445f0a3c979a112a3afb10a24e245",
    },
    // Source: pyca/cryptography (Count=9)
    GcmVector {
        key: "798706b651033d9e9bf2ce064fb12be7df7308cf45df44776588cd391c49ff85",
        nonce: "5a43368a39e7ffb775edfaf4",
        pt: "",
        aad: "926b74fe6381ebd35757e42e8e557601f2287bfc133a13fd86d61c01aa84f39713bf99a8dc07b812f0274c9d3280a138",
        ct: "",
        tag: "89fe481a3d95c03a0a9d4ee3e3f0ed4a",
    },
    // Source: pyca/cryptography (Count=10)
    GcmVector {
        key: "c3aa2a39a9fef4a466618d1288bb62f8da7b1cb760ccc8f1be3e99e076f08eff",
        nonce: "9965ba5e23d9453d7267ca5b",
        pt: "",
        aad: "93efb6a2affc304cb25dfd49aa3e3ccdb25ceac3d3cea90dd99e38976978217ad5f2b990d10b91725c7fd2035ecc6a30",
        ct: "",
        tag: "00a94c18a4572dcf4f9e2226a03d4c07",
    },
    // Source: pyca/cryptography (Count=11)
    GcmVector {
        key: "14e06858008f7e77186a2b3a7928a0c7fcee22136bc36f53553f20fa5c37edcd",
        nonce: "32ebe0dc9ada849b5eda7b48",
        pt: "",
        aad: "6c0152abfa485b8cd67c154a5f0411f22121379774d745f40ee577b028fd0e188297581561ae972223d75a24b488aed7",
        ct: "",
        tag: "2625b0ba6ee02b58bc529e43e2eb471b",
    },
    // Source: pyca/cryptography (Count=12)
    GcmVector {
        key: "fbb56b11c51a093ce169a6990399c4d741f62b3cc61f9e8a609a1b6ae8e7e965",
        nonce: "9c5a953247e91aceceb9defb",
        pt: "",
        aad: "46cb5c4f617916a9b1b2e03272cb0590ce716498533047d73c81e4cbe9278a3686116f5632753ea2df52efb3551aea2d",
        ct: "",
        tag: "4f3b82e6be4f08756071f2c46c31fedf",
    },
    // Source: pyca/cryptography (Count=13)
    GcmVector {
        key: "b303bf02f6a8dbb5bc4baccab0800db5ee06de648e2fae299b95f135c9b107cc",
        nonce: "906495b67ef4ce00b44422fa",
        pt: "",
        aad: "872c6c370926535c3fa1baec031e31e7c6c82808c8a060742dbef114961c314f1986b2131a9d91f30f53067ec012c6b7",
        ct: "",
        tag: "64dde37169082d181a69107f60c5c6bb",
    },
    // Source: pyca/cryptography (Count=14)
    GcmVector {
        key: "29f5f8075903063cb6d7050669b1f74e08a3f79ef566292dfdef1c06a408e1ab",
        nonce: "35f25c48b4b5355e78b9fb3a",
        pt: "",
        aad: "107e2e23159fc5c0748ca7a077e5cc053fa5c682ff5269d350ee817f8b5de4d3972041d107b1e2f2e54ca93b72cd0408",
        ct: "",
        tag: "fee5a9baebb5be0165deaa867e967a9e",
    },
    // Source: pyca/cryptography (Count=0)
    GcmVector {
        key: "03ccb7dbc7b8425465c2c3fc39ed0593929ffd02a45ff583bd89b79c6f646fe9",
        nonce: "fd119985533bd5520b301d12",
        pt: "",
        aad: "98e68c10bf4b5ae62d434928fc6405147c6301417303ef3a703dcfd2c0c339a4d0a89bd29fe61fecf1066ab06d7a5c31a48ffbfed22f749b17e9bd0dc1c6f8fbd6fd4587184db964d5456132106d782338c3f117ec05229b0899",
        ct: "",
        tag: "cf54e7141349b66f248154427810c87a",
    },
    // Source: pyca/cryptography (Count=1)
    GcmVector {
        key: "57e112cd45f2c57ddb819ea651c206763163ef016ceead5c4eae40f2bbe0e4b4",
        nonce: "188022c2125d2b1fcf9e4769",
        pt: "",
        aad: "09c8f445ce5b71465695f838c4bb2b00624a1c9185a3d552546d9d2ee4870007aaf3007008f8ae9affb7588b88d09a90e58b457f88f1e3752e3fb949ce378670b67a95f8cf7f5c7ceb650efd735dbc652cae06e546a5dbd861bd",
        ct: "",
        tag: "9efcddfa0be21582a05749f4050d29fe",
    },
    // Source: pyca/cryptography (Count=2)
    GcmVector {
        key: "a4ddf3cab7453aaefad616fd65d63d13005e9459c17d3173cd6ed7f2a86c921f",
        nonce: "06177b24c58f3be4f3dd4920",
        pt: "",
        aad: "f95b046d80485e411c56b834209d3abd5a8a9ddf72b1b916679adfdde893044315a5f4967fd0405ec297aa332f676ff0fa5bd795eb609b2e4f088db1cdf37ccff0735a5e53c4c12173a0026aea42388a7d7153a8830b8a901cf9",
        ct: "",
        tag: "9d1bd8ecb3276906138d0b03fcb8c1bb",
    },
    // Source: pyca/cryptography (Count=3)
    GcmVector {
        key: "24a92b24e85903cd4aaabfe07c310df5a4f8f459e03a63cbd1b47855b09c0be8",
        nonce: "22e756dc898d4cf122080612",
        pt: "",
        aad: "2e01b2536dbe376be144296f5c38fb099e008f962b9f0e896334b6408393bff1020a0e442477abfdb1727213b6ccc577f5e16cb057c8945a07e307264b65979aed96b5995f40250ffbaaa1a1f0eccf394015f6290f5e64dfe5ca",
        ct: "",
        tag: "0d7f1aed4708a03b0c80b2a18785c96d",
    },
    // ── Additional vectors generated and verified with pyca/cryptography (OpenSSL backend) ──
    // Source: pyca/cryptography verified – BoringSSL style short plaintext
    GcmVector {
        key: "e5ac4a32c67e425bae6c19d2e25f0e8a3d0de5502cc3b1ee4ef83f16e75f2e29",
        nonce: "5bf11a0951f0bfc81e2a0750",
        pt: "54657374696e672031203220332e",
        aad: "",
        ct: "13f9e79f7c0627be185474023c2c",
        tag: "92a13cc6519f9ee5dc0c7e11b6e29490",
    },
    // Source: pyca/cryptography verified – 256-byte zero plaintext
    GcmVector {
        key: "4c8ebfe1444ec1b2d503c6986659af2c94fafe945f0ec25f043bde6ef0fa8f0a",
        nonce: "473360e0ad24889959858282",
        pt: "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        aad: "",
        ct: "4e557bbaa946e00f5d152e5cb33aef3a06270dcc4d97bfc33a7857414140b316b6a99b0490b5bc02a2de20c7ddc02a2bc7a6a0591d2e2ff56fda74780dbc8745154314e9484dd8683b9ce893081c7306a45db1e8ca5f02bd688bb182a3e293362efca92c85c8b7cfe83cc2f70084877dbcecf57469c6fe2c990722355fab1f43530c465424ed1bf7f03b93c403b005a40ea9238f4c2c816d1d9af48ddad9c7d1e8abf11d00f38110867c720fdddcfa0769cc39daf81178c82ab960c3309200610a42e5219c920e8a5c0b30c360218e80f7418fa4a9e556f199da87636616bf27b484a4bef1db582a0a11a5f20a9b5ecdce3e703f98086b13e453cc16f3d87e51",
        tag: "b2c3a2b04f167587e821f50efce64b0c",
    },
    // Source: pyca/cryptography verified – Large AAD (128 bytes) with 32-byte plaintext
    GcmVector {
        key: "2f1e0a2fc2355b7e18b6adab7ccbe8a27e3e3faab3f06f26d3e1fe2e69ab3bff",
        nonce: "a91cd374a3a4362fd1f30e2f",
        pt: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        aad: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        ct: "4009a0f359798995faa7f3610d7fab81a097fc171619940082b381453bc512dc",
        tag: "10add57efc77a4bcb30e94a82dbe8c1a",
    },
    // Source: pyca/cryptography verified – Single byte plaintext with AAD
    GcmVector {
        key: "3881e7be1bb3bbcbcda0f07b7a4471e6ae18e5f0e93a6cb14647c2de85ffbeef",
        nonce: "dcf5b7ae2f0f4d2684f2baae",
        pt: "42",
        aad: "deadbeef",
        ct: "d5",
        tag: "b32d586e094a7e2fa2bb86d2df7adc02",
    },
    // Source: pyca/cryptography verified – 15-byte plaintext (sub-block)
    GcmVector {
        key: "a4bc10b1a62c96d459fbaf3a5aa3face7313bb9e1253e696f96a7a8e36801088",
        nonce: "a544218dadd3c10583db49cf",
        pt: "00112233445566778899aabbccddee",
        aad: "",
        ct: "315167cf54ba0d2d37270b4b93cd66",
        tag: "b5e0791ac0672c38a845503137f797e1",
    },
    // Source: pyca/cryptography verified – 17-byte plaintext (just over one block) with AAD
    GcmVector {
        key: "8395fcf1e95bebd697bd010bc766aac3af96bdf3e4f916e6f67e5561bb8e9f96",
        nonce: "0e8d0b2d38e0f8d7a68ce2ad",
        pt: "00112233445566778899aabbccddeeff11",
        aad: "4142434445464748",
        ct: "3a810ec7d35ff484224c7327724fde4393",
        tag: "1472036169976e5a36ff68daa3078d3e",
    },
    // Source: pyca/cryptography verified – MAC-only with 128-byte AAD
    GcmVector {
        key: "014c9214862a18d2b46384e25c1a1c0030476defd1ea39d29a1cee84eca15b05",
        nonce: "0b7fdbfb25e1bc9daae8a28c",
        pt: "",
        aad: "aabbccddeeff0011aabbccddeeff0011aabbccddeeff0011aabbccddeeff0011aabbccddeeff0011aabbccddeeff0011aabbccddeeff0011aabbccddeeff0011aabbccddeeff0011aabbccddeeff0011aabbccddeeff0011aabbccddeeff0011aabbccddeeff0011aabbccddeeff0011aabbccddeeff0011aabbccddeeff0011",
        ct: "",
        tag: "4b41034df2152a1b22f3d68dee395e24",
    },
    // Source: pyca/cryptography verified – Multi-block (64-byte PT, 32-byte AAD)
    GcmVector {
        key: "b52c505a37d78eda5dd34f20c22540ea1b58963cf8e5bf8ffa85f9f2492505b4",
        nonce: "516c33929df5a3284ff463d7",
        pt: "00010203040506070001020304050607000102030405060700010203040506070001020304050607000102030405060700010203040506070001020304050607",
        aad: "0001020304050607000102030405060700010203040506070001020304050607",
        ct: "e69c8e689b8eb6386bfdcb2509d4c21797fec618d7c56b4ab1cf8c37e1db437a3f21a04732b8a2a6e5d1f2985fa06f9e848c3f5f115142580adf65e57a6c863f",
        tag: "1fa8e4f994d15d7cfff7315b487c6713",
    },
    // Source: pyca/cryptography verified – Incrementing pattern (NIST CAVP style)
    GcmVector {
        key: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        nonce: "000102030405060708090a0b",
        pt: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        aad: "000102030405060708090a0b0c0d0e0f",
        ct: "4703d418c1e0c41c85489d80bde4766293c79527e46e496b207eff9e01741ead",
        tag: "209d59e08347d37153a593a1fca88881",
    },
    // Source: pyca/cryptography verified – All-ones key, plaintext, and AAD
    GcmVector {
        key: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        nonce: "ffffffffffffffffffffffff",
        pt: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        aad: "ffffffffffffffffffffffffffffffff",
        ct: "42c4417ae76f276beb09973a4b9b3715e6a0fc4d53cb94e7338af461b0837bc1",
        tag: "6f1e9ac49421d9ca6e6720b4d22e0cbe",
    },
    // Source: pyca/cryptography verified – Alternating bit patterns
    GcmVector {
        key: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        nonce: "555555555555555555555555",
        pt: "aa55aa55aa55aa55aa55aa55aa55aa55aa55aa55aa55aa55aa55aa55aa55aa55",
        aad: "55aa55aa55aa55aa55aa55aa55aa55aa",
        ct: "629139940711d698f7e956430f425b1f51b3f03ef647a1d1479b7cb552616acd",
        tag: "9ead0bc82db5a46ef03ac3195ab1de05",
    },
    // Source: pyca/cryptography verified – 3-block (48-byte) plaintext
    GcmVector {
        key: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        nonce: "fedcba9876543210fedc0123",
        pt: "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899",
        aad: "",
        ct: "de7384a1c9f8fe4fa022a7ff71525ec36723d5f17b0f06e7d656911c9c39c457d1429ffd70d17430f029846ad6639781",
        tag: "7bf9dce9edcf955f0cd751bd46cdb943",
    },
    // Source: pyca/cryptography verified – 5-block (80-byte) PT with 3-block (48-byte) AAD
    GcmVector {
        key: "deadbeefcafebabedeadbeefcafebabedeadbeefcafebabedeadbeefcafebabe",
        nonce: "0bad0bad0bad0bad0bad0bad",
        pt: "48656c6c6f20576f726c642148656c6c6f20576f726c642148656c6c6f20576f726c642148656c6c6f20576f726c642148656c6c6f20576f726c642148656c6c6f20576f726c642148656c6c6f20576f",
        aad: "416464206d65746164617461416464206d65746164617461416464206d65746164617461416464206d65746164617461",
        ct: "7caf8fe2c0f2ee0fd0282c977620fa0c65cb448dae9ed89922a4dfbe387a26489265b9b8c2258f19dd2d4b29c13aa19be755220e3f0ff57dc2ac49fd1f8f1f4500fcae6fa6c102e23c1822013ff695b9",
        tag: "804e1175cb90bef1bb3ac867e1f104d3",
    },
    // Source: pyca/cryptography verified – 2-block PT with 1-byte AAD
    GcmVector {
        key: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        nonce: "bbbbbbbbbbbbbbbbbbbbbbbb",
        pt: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        aad: "dd",
        ct: "06dd876abad19614fc58615121a916d6794c3bf745fca14124b777efbc12e163",
        tag: "f537f82fe5c633b0bcbb74a47857ab69",
    },
    // Source: pyca/cryptography verified – 31-byte PT with 20-byte AAD
    GcmVector {
        key: "1111111111111111111111111111111122222222222222222222222222222222",
        nonce: "333333333333333333333333",
        pt: "44444444444444444444444444444444444444444444444444444444444444",
        aad: "5555555555555555555555555555555555555555",
        ct: "6d5fe7e7516f31d40a33a1c254ca67b5e95bbe82f28cc454c689b4e5efab79",
        tag: "06ac4b2c8b5bca4823c61b28bc2c27fc",
    },
    // ── BoringSSL test vectors (google/boringssl crypto/cipher/test/aes_256_gcm_tests.txt) ──
    // Source: BoringSSL – empty PT, empty AAD
    GcmVector {
        key: "e5ac4a32c67e425ac4b143c83c6f161312a97d88d634afdf9f4da5bd35223f01",
        nonce: "5bf11a0951f0bfc7ea5c9e58",
        pt: "",
        aad: "",
        ct: "",
        tag: "d7cba289d6d19a5af45dc13857016bac",
    },
    // Source: BoringSSL – 5-byte PT + 5-byte AAD
    GcmVector {
        key: "73ad7bbbbc640c845a150f67d058b279849370cd2c1f3c67c4dd6c869213e13a",
        nonce: "a330a184fc245812f4820caa",
        pt: "f0535fe211",
        aad: "e91428be04",
        ct: "e9b8a896da",
        tag: "9115ed79f26a030c14947b3e454db9e7",
    },
    // Source: BoringSSL – 15-byte PT + 15-byte AAD
    GcmVector {
        key: "881cca012ef9d6f1241b88e4364084d8c95470c6022e59b62732a1afcc02e657",
        nonce: "172ec639be736062bba5c32f",
        pt: "8ed8ef4c09360ef70bb22c716554ef",
        aad: "98c115f2c3bbe22e3a0c562e8e67ff",
        ct: "06a761987a7eb0e57a31979043747d",
        tag: "cf07239b9d40a759e0f4f8ef088f016a",
    },
    // Source: BoringSSL – 30-byte PT + 30-byte AAD
    GcmVector {
        key: "525429d45a66b9d860c83860111cc65324ab91ff77938bbc30a654220bb3e526",
        nonce: "31535d82b9b46f5ad75a1629",
        pt: "677eca74660499acf2e2fd6c7800fd6da2d0273a31906a691205b5765b85",
        aad: "513bc218acee89848e73ab108401bfc4f9c2aa70310a4e543644c37dd2f3",
        ct: "f1e6032ee3ce224b2e8f17f91055c81a480398e07fd9366ad69d84dca712",
        tag: "e39da5658f1d2994a529646d692c55d8",
    },
];
