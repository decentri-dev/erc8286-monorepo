// SPDX-License-Identifier: MIT

// Stateless singleton bridge for the Hegotá frame-transaction opcode family
// (EIP-8141 + EIP-8250 + EIP-8272 + EIP-7906) unsupported by standard solc.
// Deploy once per chain and point Solidity accounts/validators at it.
//
// Opcode bytes and TXPARAM indices follow the Hegotá devnet allocation
// (ethrex docs/hegota-devnet.md), NOT the draft specs where they diverge:
//   TXPARAM 0xB0 (nonce_keys[0] at index 0x10, not the spec's 0x0B),
//   RECENTROOTREFLOAD 0xB5 (spec 0xB4), TXTRACE 0xB6 / EVENTDATACOPY 0xB7 /
//   TXDIFF 0xB8 (spec 0xB5/0xB6/0xB7).
//
// verbatim argument order: solc places the FIRST verbatim argument on top of
// the stack (standard Yul builtin convention), so each helper lists operands
// in the exact order the LEVM handler pops them.
//
// Read helpers can be called normally/staticcalled. approve* helpers must be
// delegatecalled from the resolved target account so APPROVE observes the
// account's ADDRESS. txTrace/txDiff/eventDataCopy exceptional-halt unless the
// call chain is inside a POST_TX frame's subtree.
object "FrameOpcodeAdapter" {
    code {
        datacopy(0x00, dataoffset("Runtime"), datasize("Runtime"))
        return(0x00, datasize("Runtime"))
    }

    object "Runtime" {
        code {
            function revert0() { revert(0, 0) }

            function revertErr(sel) {
                mstore(0x00, shl(224, sel))
                revert(0x00, 0x04)
            }

            function selector() -> sig {
                if lt(calldatasize(), 4) { revert0() }
                sig := shr(224, calldataload(0))
            }

            function round32(n) -> r {
                r := and(add(n, 31), not(31))
            }

            function txparam(param_) -> value {
                value := verbatim_1i_1o(hex"b0", param_)
            }

            // FRAMEDATALOAD pops offset first, then frameIndex.
            function framedataload(offset_, frameIndex_) -> value {
                value := verbatim_2i_1o(hex"b1", offset_, frameIndex_)
            }

            function framedatacopy(memOffset_, dataOffset_, length_, frameIndex_) {
                verbatim_4i_0o(hex"b2", memOffset_, dataOffset_, length_, frameIndex_)
            }

            function frameparam(frameIndex_, param_) -> value {
                value := verbatim_2i_1o(hex"b3", frameIndex_, param_)
            }

            function sigparam(signatureIndex_, param_) -> value {
                value := verbatim_2i_1o(hex"b4", signatureIndex_, param_)
            }

            // EIP-8272: pops field first (0 source_id, 1 slot, 2 root), then index.
            function recentrootrefload(field_, index_) -> value {
                value := verbatim_2i_1o(hex"b5", field_, index_)
            }

            // EIP-7906: pops in2 first, then param. POST_TX frames only.
            function txtrace(in2_, param_) -> value {
                value := verbatim_2i_1o(hex"b6", in2_, param_)
            }

            // EIP-7906: pops eventIndex, memOffset, dataOffset, length. POST_TX only.
            function eventdatacopy(eventIndex_, memOffset_, dataOffset_, length_) {
                verbatim_4i_0o(hex"b7", eventIndex_, memOffset_, dataOffset_, length_)
            }

            // EIP-7906: pops param, address, in3. POST_TX frames only.
            function txdiff(param_, addr_, in3_) -> value {
                value := verbatim_3i_1o(hex"b8", param_, addr_, in3_)
            }

            function approve8141(offset_, length_, scope_) {
                verbatim_3i_0o(hex"aa", offset_, length_, scope_)
            }

            function returnWord(value) {
                mstore(0x00, value)
                return(0x00, 0x20)
            }

            switch selector()

            // txParam(uint256) -> uint256
            case 0x16525c7f {
                returnWord(txparam(calldataload(4)))
            }

            // frameDataLoad(uint256,uint256) -> bytes32
            case 0x7129a8fe {
                let frameIndex := calldataload(4)
                let offset := calldataload(36)
                returnWord(framedataload(offset, frameIndex))
            }

            // frameDataCopy(uint256,uint256,uint256) -> bytes
            case 0x03f2f011 {
                let frameIndex := calldataload(4)
                let offset := calldataload(36)
                let length := calldataload(68)
                mstore(0x00, 0x20)
                mstore(0x20, length)
                framedatacopy(0x40, offset, length, frameIndex)
                return(0x00, add(0x40, round32(length)))
            }

            // frameData(uint256) -> bytes
            case 0xb6481b8f {
                let frameIndex := calldataload(4)
                let length := frameparam(frameIndex, 0x04)
                mstore(0x00, 0x20)
                mstore(0x20, length)
                framedatacopy(0x40, 0, length, frameIndex)
                return(0x00, add(0x40, round32(length)))
            }

            // frameDataHash(uint256) -> bytes32
            case 0x9da7f7de {
                let frameIndex := calldataload(4)
                let length := frameparam(frameIndex, 0x04)
                framedatacopy(0x00, 0, length, frameIndex)
                returnWord(keccak256(0x00, length))
            }

            // frameParam(uint256,uint256) -> uint256
            case 0xff846610 {
                let frameIndex := calldataload(4)
                let param := calldataload(36)
                returnWord(frameparam(frameIndex, param))
            }

            // sigParam(uint256,uint256) -> uint256
            case 0xf457766f {
                let signatureIndex := calldataload(4)
                let param := calldataload(36)
                returnWord(sigparam(signatureIndex, param))
            }

            // nonceKey(uint256) -> uint256
            // Only nonce_keys[0] is exposed by the devnet (TXPARAM 0x10);
            // reverts NonceKeyOutOfRange for index >= count and
            // NonceKeyNotExposed for 0 < index < count.
            case 0x3b325fc5 {
                let index := calldataload(4)
                if iszero(lt(index, txparam(0x0d))) { revertErr(0x585ce152) }
                if index { revertErr(0x01aaf121) }
                returnWord(txparam(0x10))
            }

            // nonceKeyCount() -> uint256
            case 0x1caaa756 {
                returnWord(txparam(0x0d))
            }

            // nonceKeysHash() -> bytes32
            case 0x7658c021 {
                returnWord(txparam(0x0e))
            }

            // legacySenderNonce() -> uint256
            case 0x78eadd88 {
                returnWord(txparam(0x0c))
            }

            // recentRootRefCount() -> uint256
            case 0xd66dcfc0 {
                returnWord(txparam(0x0f))
            }

            // recentRootRef(uint256) -> (bytes32 sourceId, uint256 slot, bytes32 root)
            case 0x4d963f56 {
                let index := calldataload(4)
                if iszero(lt(index, txparam(0x0f))) { revertErr(0xdaf34e19) }
                mstore(0x00, recentrootrefload(0, index))
                mstore(0x20, recentrootrefload(1, index))
                mstore(0x40, recentrootrefload(2, index))
                return(0x00, 0x60)
            }

            // recentRootRefLoad(uint256,uint256) -> uint256
            // Raw passthrough; out-of-bounds index or field > 2 exceptional-halts.
            case 0xe16864e9 {
                let index := calldataload(4)
                let field := calldataload(36)
                returnWord(recentrootrefload(field, index))
            }

            // txTrace(uint256,uint256) -> uint256
            case 0xb167be16 {
                let param := calldataload(4)
                let in2 := calldataload(36)
                returnWord(txtrace(in2, param))
            }

            // txDiff(uint256,address,uint256) -> uint256
            case 0xe899884e {
                let param := calldataload(4)
                let addr := calldataload(36)
                let in3 := calldataload(68)
                returnWord(txdiff(param, addr, in3))
            }

            // eventDataCopy(uint256,uint256,uint256) -> bytes
            // Past-the-end reads exceptional-halt (no zero-fill), unlike
            // frameDataCopy's CALLDATACOPY-style padding.
            case 0x9666f50f {
                let eventIndex := calldataload(4)
                let dataOffset := calldataload(36)
                let length := calldataload(68)
                mstore(0x00, 0x20)
                mstore(0x20, length)
                eventdatacopy(eventIndex, 0x40, dataOffset, length)
                return(0x00, add(0x40, round32(length)))
            }

            // approve(uint8)
            case 0xfca0025d {
                approve8141(0, 0, calldataload(4))
                stop()
            }

            // approveWithData(bytes,uint8)
            case 0xd8ac582b {
                let dataHead := calldataload(4)
                let scope := calldataload(36)
                let dataLengthOffset := add(4, dataHead)
                let length := calldataload(dataLengthOffset)
                calldatacopy(0x00, add(dataLengthOffset, 32), length)
                approve8141(0x00, length, scope)
                stop()
            }

            default {
                revert0()
            }
        }
    }
}
