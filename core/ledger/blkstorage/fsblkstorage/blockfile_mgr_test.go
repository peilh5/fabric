/*
Copyright IBM Corp. 2016 All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

		 http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package fsblkstorage

import (
	"fmt"
	"testing"

	"github.com/golang/protobuf/proto"
	"github.com/hyperledger/fabric/core/ledger/testutil"

	"github.com/hyperledger/fabric/protos/common"
	pb "github.com/hyperledger/fabric/protos/peer"
)

func TestBlockfileMgrBlockReadWrite(t *testing.T) {
	env := newTestEnv(t, NewConf("/tmp/fabric/ledgertests", 0))
	defer env.Cleanup()
	blkfileMgrWrapper := newTestBlockfileWrapper(env, "testLedger")
	defer blkfileMgrWrapper.close()
	blocks := testutil.ConstructTestBlocks(t, 10)
	blkfileMgrWrapper.addBlocks(blocks)
	blkfileMgrWrapper.testGetBlockByHash(blocks)
	blkfileMgrWrapper.testGetBlockByNumber(blocks, 1)
}

func TestBlockfileMgrCrashDuringWriting(t *testing.T) {
	testBlockfileMgrCrashDuringWriting(t, 10, 2, 1000, 10)
	testBlockfileMgrCrashDuringWriting(t, 10, 2, 1000, 1)
	testBlockfileMgrCrashDuringWriting(t, 10, 2, 1000, 0)
	testBlockfileMgrCrashDuringWriting(t, 0, 0, 1000, 10)
}

func testBlockfileMgrCrashDuringWriting(t *testing.T, numBlocksBeforeCheckpoint int,
	numBlocksAfterCheckpoint int, numLastBlockBytes int, numPartialBytesToWrite int) {
	env := newTestEnv(t, NewConf("/tmp/fabric/ledgertests", 0))
	defer env.Cleanup()
	ledgerid := "testLedger"
	blkfileMgrWrapper := newTestBlockfileWrapper(env, ledgerid)
	bg := testutil.NewBlockGenerator(t)
	blocksBeforeCP := bg.NextTestBlocks(numBlocksBeforeCheckpoint)
	blkfileMgrWrapper.addBlocks(blocksBeforeCP)
	currentCPInfo := blkfileMgrWrapper.blockfileMgr.cpInfo
	cpInfo1 := &checkpointInfo{
		currentCPInfo.latestFileChunkSuffixNum,
		currentCPInfo.latestFileChunksize,
		currentCPInfo.lastBlockNumber}

	blocksAfterCP := bg.NextTestBlocks(numBlocksAfterCheckpoint)
	blkfileMgrWrapper.addBlocks(blocksAfterCP)
	cpInfo2 := blkfileMgrWrapper.blockfileMgr.cpInfo

	// simulate a crash scenario
	lastBlockBytes := []byte{}
	encodedLen := proto.EncodeVarint(uint64(numLastBlockBytes))
	randomBytes := testutil.ConstructRandomBytes(t, numLastBlockBytes)
	lastBlockBytes = append(lastBlockBytes, encodedLen...)
	lastBlockBytes = append(lastBlockBytes, randomBytes...)
	partialBytes := lastBlockBytes[:numPartialBytesToWrite]
	blkfileMgrWrapper.blockfileMgr.currentFileWriter.append(partialBytes, true)
	blkfileMgrWrapper.blockfileMgr.saveCurrentInfo(cpInfo1, true)
	blkfileMgrWrapper.close()

	// simulate a start after a crash
	blkfileMgrWrapper = newTestBlockfileWrapper(env, ledgerid)
	defer blkfileMgrWrapper.close()
	cpInfo3 := blkfileMgrWrapper.blockfileMgr.cpInfo
	testutil.AssertEquals(t, cpInfo3, cpInfo2)

	// add fresh blocks after restart
	blocksAfterRestart := bg.NextTestBlocks(2)
	blkfileMgrWrapper.addBlocks(blocksAfterRestart)
	allBlocks := []*common.Block{}
	allBlocks = append(allBlocks, blocksBeforeCP...)
	allBlocks = append(allBlocks, blocksAfterCP...)
	allBlocks = append(allBlocks, blocksAfterRestart...)
	testBlockfileMgrBlockIterator(t, blkfileMgrWrapper.blockfileMgr, 1, len(allBlocks), allBlocks)
}

func TestBlockfileMgrBlockIterator(t *testing.T) {
	env := newTestEnv(t, NewConf("/tmp/fabric/ledgertests", 0))
	defer env.Cleanup()
	blkfileMgrWrapper := newTestBlockfileWrapper(env, "testLedger")
	defer blkfileMgrWrapper.close()
	blocks := testutil.ConstructTestBlocks(t, 10)
	blkfileMgrWrapper.addBlocks(blocks)
	testBlockfileMgrBlockIterator(t, blkfileMgrWrapper.blockfileMgr, 1, 8, blocks[0:8])
}

func testBlockfileMgrBlockIterator(t *testing.T, blockfileMgr *blockfileMgr,
	firstBlockNum int, lastBlockNum int, expectedBlocks []*common.Block) {
	itr, err := blockfileMgr.retrieveBlocks(uint64(firstBlockNum))
	defer itr.Close()
	testutil.AssertNoError(t, err, "Error while getting blocks iterator")
	numBlocksItrated := 0
	for {
		block, err := itr.Next()
		testutil.AssertNoError(t, err, fmt.Sprintf("Error while getting block number [%d] from iterator", numBlocksItrated))
		testutil.AssertEquals(t, block.(*blockHolder).GetBlock(), expectedBlocks[numBlocksItrated])
		numBlocksItrated++
		if numBlocksItrated == lastBlockNum-firstBlockNum+1 {
			break
		}
	}
	testutil.AssertEquals(t, numBlocksItrated, lastBlockNum-firstBlockNum+1)
}

func TestBlockfileMgrBlockchainInfo(t *testing.T) {
	env := newTestEnv(t, NewConf("/tmp/fabric/ledgertests", 0))
	defer env.Cleanup()
	blkfileMgrWrapper := newTestBlockfileWrapper(env, "testLedger")
	defer blkfileMgrWrapper.close()

	bcInfo := blkfileMgrWrapper.blockfileMgr.getBlockchainInfo()
	testutil.AssertEquals(t, bcInfo, &pb.BlockchainInfo{Height: 0, CurrentBlockHash: nil, PreviousBlockHash: nil})

	blocks := testutil.ConstructTestBlocks(t, 10)
	blkfileMgrWrapper.addBlocks(blocks)
	bcInfo = blkfileMgrWrapper.blockfileMgr.getBlockchainInfo()
	testutil.AssertEquals(t, bcInfo.Height, uint64(10))
}

func TestBlockfileMgrGetTxById(t *testing.T) {
	env := newTestEnv(t, NewConf("/tmp/fabric/ledgertests", 0))
	defer env.Cleanup()
	blkfileMgrWrapper := newTestBlockfileWrapper(env, "testLedger")
	defer blkfileMgrWrapper.close()
	blocks := testutil.ConstructTestBlocks(t, 10)
	blkfileMgrWrapper.addBlocks(blocks)
	for _, blk := range blocks {
		for j, txEnvelopeBytes := range blk.Data.Data {
			// blockNum starts with 1
			txID, err := extractTxID(blk.Data.Data[j])
			testutil.AssertNoError(t, err, "")
			txFromFileMgr, err := blkfileMgrWrapper.blockfileMgr.retrieveTransactionByID(txID)
			testutil.AssertNoError(t, err, "Error while retrieving tx from blkfileMgr")
			tx, err := extractTransaction(txEnvelopeBytes)
			testutil.AssertNoError(t, err, "Error while unmarshalling tx")
			testutil.AssertEquals(t, txFromFileMgr, tx)
		}
	}
}

func TestBlockfileMgrRestart(t *testing.T) {
	env := newTestEnv(t, NewConf("/tmp/fabric/ledgertests", 0))
	defer env.Cleanup()
	ledgerid := "testLedger"
	blkfileMgrWrapper := newTestBlockfileWrapper(env, ledgerid)
	blocks := testutil.ConstructTestBlocks(t, 10)
	blkfileMgrWrapper.addBlocks(blocks)
	blkfileMgrWrapper.close()

	blkfileMgrWrapper = newTestBlockfileWrapper(env, ledgerid)
	defer blkfileMgrWrapper.close()
	testutil.AssertEquals(t, int(blkfileMgrWrapper.blockfileMgr.cpInfo.lastBlockNumber), 10)
	blkfileMgrWrapper.testGetBlockByHash(blocks)
}

func TestBlockfileMgrFileRolling(t *testing.T) {
	blocks := testutil.ConstructTestBlocks(t, 100)
	size := 0
	for _, block := range blocks {
		by, _, err := serializeBlock(block)
		testutil.AssertNoError(t, err, "Error while serializing block")
		blockBytesSize := len(by)
		encodedLen := proto.EncodeVarint(uint64(blockBytesSize))
		size += blockBytesSize + len(encodedLen)
	}

	maxFileSie := int(0.75 * float64(size))
	env := newTestEnv(t, NewConf("/tmp/fabric/ledgertests", maxFileSie))
	defer env.Cleanup()
	ledgerid := "testLedger"
	blkfileMgrWrapper := newTestBlockfileWrapper(env, ledgerid)
	blkfileMgrWrapper.addBlocks(blocks)
	testutil.AssertEquals(t, blkfileMgrWrapper.blockfileMgr.cpInfo.latestFileChunkSuffixNum, 1)
	blkfileMgrWrapper.testGetBlockByHash(blocks)
	blkfileMgrWrapper.close()

	blkfileMgrWrapper = newTestBlockfileWrapper(env, ledgerid)
	defer blkfileMgrWrapper.close()
	blkfileMgrWrapper.addBlocks(blocks)
	testutil.AssertEquals(t, blkfileMgrWrapper.blockfileMgr.cpInfo.latestFileChunkSuffixNum, 2)
	blkfileMgrWrapper.testGetBlockByHash(blocks)
}
