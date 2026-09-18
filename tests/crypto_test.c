#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "crypto/tetra_crypto.h"

static void write_file(const char *path, const char *contents)
{
    FILE *file = fopen(path, "w");
    assert(file);
    assert(fputs(contents, file) >= 0);
    assert(fclose(file) == 0);
}

int main(void)
{
    struct tetra_crypto_database db;
    struct tetra_crypto_state state;
    struct tetra_tdma_time time = { .tn = 1, .fn = 1, .mn = 1 };
    const char *path = "tetra_crypto_test.keys";
    char error[160];

    tetra_crypto_db_init(&db);
    tetra_crypto_state_init(&state);
    state.db = &db;

    {
        struct tetra_tmvsap_prim primitive = {0};
        struct tetra_key key = {0};
        assert(!decrypt_mac_element(&state, &primitive, &key, 100, -1));
        assert(!decrypt_mac_element(&state, &primitive, &key, 100, 100));
    }

    assert(tea_build_iv(&time, 0, 0) == (1u << 2 | 1u << 7));
    time.tn = 4; time.fn = 18; time.mn = 60;
    assert(tea_build_iv(&time, 0x1234, 1) ==
           (3u | 18u << 2 | 60u << 7 | 0x1234u << 13 | 1u << 28));

    write_file(path,
        "# synthetic test data only\n"
        "network mcc 1 mnc 2 ksg_type 1 security_class 2\n"
        "key mcc 1 mnc 2 addr 0 key_type 1 key_num 3 key 00010203040506070809\n");
    assert(tetra_crypto_db_load(&db, path, error, sizeof(error)) == 0);
    assert(db.num_nets == 1 && db.num_keys == 1);
    update_current_network(&state, 1, 2);
    state.cck_id = 3;
    update_current_cck(&state);
    assert(state.network && state.cck);

    /* A failed transactional reload leaves the active database intact. */
    write_file(path, "key malformed\n");
    assert(tetra_crypto_db_load(&db, path, error, sizeof(error)) < 0);
    assert(error[0] && db.num_nets == 1 && db.num_keys == 1);

    /* Repeated load/clear is safe and does not retain stale storage. */
    write_file(path, "network mcc 4 mnc 5 ksg_type 3 security_class 3\n");
    assert(tetra_crypto_db_load(&db, path, error, sizeof(error)) == 0);
    assert(db.num_nets == 1 && db.num_keys == 0);
    tetra_crypto_refresh(&state);
    assert(!state.network && !state.cck);
    tetra_crypto_db_clear(&db);
    tetra_crypto_db_clear(&db);
    assert(!db.keys && !db.nets && !db.num_keys && !db.num_nets);

    /* Programmatic ingestion uses the same validation and selection layer. */
    {
        const struct tetra_netinfo network = { 10, 20, KSG_TEA2, NETWORK_CLASS_2 };
        struct tetra_key key = {0};
        key.mcc = 10; key.mnc = 20; key.key_type = KEYTYPE_CCK_SCK; key.key_num = 7;
        for (unsigned int i = 0; i < 10; i++) key.key[i] = (uint8_t)i;
        assert(tetra_crypto_db_add_or_replace(&db, &network, &key, error, sizeof(error)) == 0);
        state.cck_id = 7;
        update_current_network(&state, 10, 20);
        assert(state.network && state.cck && db.num_keys == 1);
        key.key[0] = 0xaa;
        assert(tetra_crypto_db_add_or_replace(&db, &network, &key, error, sizeof(error)) == 0);
        assert(db.num_keys == 1 && db.keys[0].key[0] == 0xaa);

        /* Synthetic voice data: applying the same stream twice must restore
         * both ETSI soft decisions and hard-bit representations. */
        {
            int16_t voice[276], original[276];
            struct tetra_tdma_time voice_time = { .tn = 2, .fn = 7, .mn = 12 };
            state.hn = 42; state.cn = 100; state.la = 200; state.cc = 3;
            update_current_network(&state, 10, 20);
            for (unsigned int i = 0; i < 276; i++)
                voice[i] = i % 3 == 0 ? 1 : (i % 2 ? 127 : -127);
            memcpy(original, voice, sizeof(voice));
            assert(decrypt_voice_timeslot(&state, &voice_time, voice));
            assert(memcmp(original, voice, sizeof(voice)) != 0);
            assert(decrypt_voice_timeslot(&state, &voice_time, voice));
            assert(memcmp(original, voice, sizeof(voice)) == 0);
        }
    }
    tetra_crypto_db_clear(&db);

    assert(remove(path) == 0);
    return 0;
}
