package com.blockparser;


import org.bitcoinj.core.Block;
import org.bitcoinj.core.Context;
import org.bitcoinj.core.NetworkParameters;
import org.bitcoinj.params.MainNetParams;
import org.bitcoinj.utils.BlockFileLoader;

import java.io.*;
import java.text.SimpleDateFormat;
import java.util.*;


/**
 * Created by Nicolas on 10/01/16.
 */
public class main {
    public static void main (String[] args) throws IOException{

// Arm the blockchain file loader.
        NetworkParameters np = new MainNetParams();
        new Context(np);
        List<File> blockChainFiles = new ArrayList<File>();
        blockChainFiles.add(new File("/Users/Nicolas/Desktop/A4S8/DolNet Project/DolNetProject/datFolder/blk00000.dat"));
        BlockFileLoader bfl = new BlockFileLoader(np, blockChainFiles);

// Data structures to keep the statistics.q
        Map<String, Integer> monthlyTxCount = new HashMap<String,Integer>();
        Map<String, Integer> monthlyBlockCount = new HashMap<String,Integer>();

// Iterate over the blocks in the dataset.
        for (Block block : bfl) {

            // Extract the month keyword.
            String month = new SimpleDateFormat("yyyy-MM--DD").format(block.getTime());
            System.out.println(month);
            // Make sure there exists an entry for the extracted month.
            if (!monthlyBlockCount.containsKey(month)) {
                monthlyBlockCount.put(month, 0);
                monthlyTxCount.put(month, 0);
            }

            // Update the statistics.
            monthlyBlockCount.put(month, 1 + monthlyBlockCount.get(month));
            monthlyTxCount.put(month, block.getTransactions().size() + monthlyTxCount.get(month));

        }

// Compute the average number of transactions per block per month.
        Map<String, Float> monthlyAvgTxCountPerBlock = new HashMap<String,Float>();
        for (String month : monthlyBlockCount.keySet())
            monthlyAvgTxCountPerBlock.put(
                    month, (float) monthlyTxCount.get(month) / monthlyBlockCount.get(month));
    }

    public static int hex2decimal(String s) {
        String digits = "0123456789ABCDEF";
        s = s.toUpperCase();
        int val = 0;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            int d = digits.indexOf(c);
            val = 16*val + d;
        }
        return val;
    }
}
