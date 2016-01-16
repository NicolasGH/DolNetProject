package com.blockparser.Testtt;


import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.NoSuchElementException;

/**
 * Created by Nicolas on 16/01/16.
 */
public class BlockFileLoader implements Iterable<Block>, Iterator<Block> {

    private long magicNumber;

    /**
     * Gets the list of files which contain blocks from the Satoshi client.
     */
    public static List<File> getReferenceClientBlockFileList() {
        String defaultDataDir;
        String OS = System.getProperty("os.name").toLowerCase();
        if (OS.indexOf("win") >= 0) {
            defaultDataDir = System.getenv("APPDATA") + "\\.bitcoin\\blocks\\";
        } else if (OS.indexOf("mac") >= 0 || (OS.indexOf("darwin") >= 0)) {
            defaultDataDir = System.getProperty("user.home") + "/Library/Application Support/Bitcoin/blocks/";
        } else {
            defaultDataDir = System.getProperty("user.home") + "/.bitcoin/blocks/";
        }

        List<File> list = new LinkedList<File>();
        for (int i = 0; true; i++) {
            File file = new File(defaultDataDir + String.format("blk%05d.dat", i));
            if (!file.exists())
                break;
            list.add(file);
        }
        return list;
    }

    private Iterator<File> fileIt;
    private FileInputStream currentFileStream = null;
    private Block nextBlock = null;

    public BlockFileLoader(List<File> files) {
        fileIt = files.iterator();
    }

    @Override
    public boolean hasNext() {
        if (nextBlock == null)
            loadNextBlock();
        return nextBlock != null;
    }

    @Override
    public Block next() throws NoSuchElementException {
        if (!hasNext())
            throw new NoSuchElementException();
        Block next = nextBlock;
        nextBlock = null;
        return next;
    }

    private void loadNextBlock() {
        this.magicNumber = 0xf9beb4d9L;
        while (true) {
            try {
                if (!fileIt.hasNext() && (currentFileStream == null || currentFileStream.available() < 1))
                    break;
            } catch (IOException e) {
                currentFileStream = null;
                if (!fileIt.hasNext())
                    break;
            }
            while (true) {
                try {
                    if (currentFileStream != null && currentFileStream.available() > 0)
                        break;
                } catch (IOException e1) {
                    currentFileStream = null;
                }
                if (!fileIt.hasNext()) {
                    nextBlock = null;
                    currentFileStream = null;
                    return;
                }
                try {
                    currentFileStream = new FileInputStream(fileIt.next());
                } catch (FileNotFoundException e) {
                    currentFileStream = null;
                }
            }
            try {
                int nextChar = currentFileStream.read();
                while (nextChar != -1) {
                    if (nextChar != ((magicNumber >>> 24) & 0xff)) {
                        nextChar = currentFileStream.read();
                        continue;
                    }
                    nextChar = currentFileStream.read();
                    if (nextChar != ((magicNumber >>> 16) & 0xff))
                        continue;
                    nextChar = currentFileStream.read();
                    if (nextChar != ((magicNumber >>> 8) & 0xff))
                        continue;
                    nextChar = currentFileStream.read();
                    if (nextChar == (magicNumber & 0xff))
                        break;
                }
                byte[] bytes = new byte[4];
                currentFileStream.read(bytes, 0, 4);
                long size = Utils.readUint32BE(Utils.reverseBytes(bytes), 0);
                // We allow larger than MAX_BLOCK_SIZE because test code uses this as well.
                if (size > Block.MAX_BLOCK_SIZE*2 || size <= 0)
                    continue;
                bytes = new byte[(int) size];
                currentFileStream.read(bytes, 0, (int) size);
                try {
                    nextBlock = new Block(bytes);
                } catch (Exception e) {
                    nextBlock = null;
                    continue;
                }
                break;
            } catch (IOException e) {
                currentFileStream = null;
                continue;
            }
        }
    }

    @Override
    public void remove() throws UnsupportedOperationException {
        throw new UnsupportedOperationException();
    }

    @Override
    public Iterator<Block> iterator() {
        return this;
    }
}


