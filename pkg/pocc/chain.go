package pocc

import (
	"github.com/mnemonik-xyz/pocc/internal/canon"
)

// SeedEncHash commits to the sealed disclosure seed.
func SeedEncHash(seedEnc []SealedBox) []byte {
	c, err := canon.Marshal(seedEnc)
	if err != nil {
		return nil
	}
	return H(TagSeedEnc, c)
}

// BootE0 computes the boot binding (spec 4.1):
//
//	e0 = H(boot ‖ h0 ‖ server_id ‖ agent_pk ‖ gpu_id ‖ r0 ‖ rand0 ‖ H(seed_enc))
func BootE0(orderHash []byte, serverID string, agentPub []byte, gpuID string,
	round uint64, randomness []byte, seedEnc []SealedBox) []byte {
	return H(TagBoot, orderHash, []byte(serverID), agentPub, []byte(gpuID),
		U64(round), randomness, SeedEncHash(seedEnc))
}

// HeartbeatE computes one chain element (spec 4.2):
//
//	e_i = H(hb ‖ e_{i-1} ‖ i ‖ r_i ‖ rand_i ‖ u_i ‖ final_i)
func HeartbeatE(prev []byte, seq, round uint64, randomness, usageCommit []byte, final bool) []byte {
	return H(TagHeartbeat, prev, U64(seq), U64(round), randomness, usageCommit, BoolByte(final))
}

// EntryLeaf is the Merkle leaf the notary anchors for one entry.
func EntryLeaf(agentPub []byte, seq uint64, e []byte) []byte {
	return H(TagEntry, agentPub, U64(seq), e)
}

// GPUNonce is the nonce passed to NVIDIA NRAS in Stage 1.
func GPUNonce(e0 []byte) []byte { return H(TagGPU, e0) }
