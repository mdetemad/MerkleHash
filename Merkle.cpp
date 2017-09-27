/**************************************************************************\
*   Author:   Mohammad Etemad                                              *
*   Date:   August 2014       (Version 1)                                  *
*                                                                          *
*   This is an implementation of Merkle Hash Tree.                         *
*   Given a text file, it reads the file in blocks of the specified size,  *
*   builds the tree and produces and verifies the membership proofs.       *
*                                                                          *
\**************************************************************************/

#include <fstream>
#include <iostream>
#include <time.h>
#include <algorithm>
#include <vector>
#include <string>
#include <map>
#include <numeric>
#include <math.h>
#include <iomanip>
#include <sstream>
#include <openssl/sha.h>

using namespace std;
typedef unsigned char byte;
string strResult;

struct Node
{
    int blockID;
    string value, hashValue;
    Node *left, *right, *parent;
};

class MerkleTree
{
    Node* root;
    int blockSize, blockNo, levels;
	const int HASHSIZE = 2 * SHA256_DIGEST_LENGTH;

    public:
    MerkleTree(int bSize) : blockSize(bSize)
    {
        levels = 0;
        blockNo = -1;
    }

    string SHA256(const string strIn)
    {
        byte hash[SHA256_DIGEST_LENGTH];
        SHA256_CTX sha256;
        SHA256_Init(&sha256);
        SHA256_Update(&sha256, strIn.c_str(), strIn.size());
        SHA256_Final(hash, &sha256);
        stringstream ss;
        for(int i = 0; i < SHA256_DIGEST_LENGTH; i++)
            ss << hex << setw(2) << setfill('0') << (int)hash[i];
        return ss.str();
    }

    // This function receives the file name,
    // reads the text un chunks of the given size, and
    // builds the Merkle hash tree accordingly.
    bool Build(const char* fileName)
    {
        ifstream inFile(fileName);
        if(!inFile.good())
            return false;

        // Now, read the file block by block of the given size.
        // And, add all blocks into a list.
        vector<Node*> listChild, listParent;
        Node *leftN = nullptr, *rightN = nullptr;
        char buffer[blockSize + 1];
        buffer[blockSize] = '\0';
        while (!inFile.eof())
        {
            inFile.read(buffer, blockSize);
            if(!inFile.gcount())
                continue;
            if(inFile.gcount() < blockSize)
                for(int i = inFile.gcount(); i < blockSize; i++)
                    buffer[i] = 'E';
            //cout << buffer << endl;
            Node* n = new Node;
            n->value = buffer;
            n->hashValue = SHA256(buffer);
            n->blockID = ++blockNo;
            n->left = n->right = n->parent = nullptr;
            listChild.push_back(n);
            //cout << "blockNo: " << blockNo << "\t" << n->hashValue << endl;
        }

        do
        {
            levels++;
        }while(pow(2, levels) <= blockNo);

        // And, build the tree over the blocks stored in the list.
        do
        {
            auto iterP = listParent.begin();
            auto doneP = listParent.end();
            while(iterP != doneP)
                listChild.push_back(*iterP++);
            listParent.clear();

            auto iter = listChild.begin();
            auto done = listChild.end();
            leftN = rightN = nullptr;
            while(iter != done)
            {
                //cout << "list: " << child->hashValue << endl;
                if(!leftN)
                    leftN = *iter++;
                else
                {
                    rightN = *iter++;
                    Node *parentN = new Node;
                    parentN->value = leftN->value;
                    parentN->hashValue = SHA256(leftN->hashValue + rightN->hashValue);
                    parentN->left = leftN;
                    parentN->right = rightN;
                    parentN->parent = nullptr;
                    parentN->blockID = -1;
                    listParent.push_back(parentN);
                    leftN->parent = rightN->parent = parentN;
                    leftN = rightN = nullptr;
                }
            }

            //cout << endl;
            if(leftN)
            {
                // Make a new NULL node:
                rightN = new Node;
                rightN->hashValue = "";
                rightN->blockID = -1;
                rightN->left = rightN->right = nullptr;

                Node *parentN = new Node;
                parentN->value = leftN->value;
                parentN->hashValue = SHA256(leftN->hashValue + rightN->hashValue);
                parentN->left = leftN;
                parentN->right = rightN;
                parentN->parent = nullptr;
                parentN->blockID = -1;
                listParent.push_back(parentN);
                leftN->parent = rightN->parent = parentN;
                leftN = rightN = nullptr;
            }

            listChild.clear();
        }while(listParent.size() > 1);

        root = listParent[0];
        return true;
    }

    // Print the leaf values for test purposes.
    void PrintTree()
    {
        Traverse(root);
        cout << endl;
    }
    
    void Traverse(const Node* tree)
    {
        if(!tree->left)
        {
            cout << tree->blockID << "\t" << tree->hashValue << endl;
            return;
        }

        Traverse(tree->left);
        Traverse(tree->right);
    }

    void Traverse2(const Node* tree)
    {
        if(!tree)
            return;
        Traverse2(tree->left);
        Traverse2(tree->right);
        cout << tree->hashValue << endl;
    }

    void UpdateHash(Node* leftN)
    {
        Node *parentN = leftN->parent, *rightN = nullptr;
        while(parentN)
        {
            if(parentN->left == leftN)
                rightN = parentN->right;
            else
            {
                rightN = leftN;
                leftN = parentN->left;
            }

            parentN->hashValue = SHA256(leftN->hashValue + rightN->hashValue);
            leftN = parentN;
            parentN = parentN->parent;
        }
    }

    // Append a new block into the tree.
    bool Append(string strBlock)
    {
        if(!strBlock.length())
        {
            cout << "Error: Empty block!" << endl;
            return false;
        }

        blockNo++;
        Node *parentN = nullptr, *leftN = nullptr, *rightN = nullptr;
        // If its a complete tree, add a new subtree and add one more level.
        if(blockNo == pow(2, levels))
        {
            cout << "1: blockNo: " << blockNo << "\tlevels: " << levels << endl;
            // Make a new root node.
            parentN = new Node;
            parentN->value = parentN->hashValue = "";
            parentN->blockID = -1;
            parentN->left = root;
            parentN->right = parentN->parent = nullptr;
            root->parent = parentN;
            root = parentN;

            parentN = new Node;
            parentN->value = parentN->hashValue = "";
            parentN->blockID = -1;
            parentN->left = parentN->right = nullptr;
            parentN->parent = root;
            root->right = parentN;

            // Make levels number of null nodes to make a new path.
            for(int i = 0; i < levels ; i++)
            {
                leftN = new Node;
                leftN->value = "";
                leftN->hashValue = SHA256("NULL");
                leftN->blockID = -1;
                leftN->left = leftN->right = nullptr;

                rightN = new Node;
                rightN->blockID = -1;
                rightN->value = "";
                rightN->hashValue = SHA256("NULL");
                rightN->left = rightN->right = nullptr;

                parentN->left = leftN;
                parentN->right = rightN;
                leftN->parent = rightN->parent = parentN;
                parentN = leftN;
            }

            leftN->blockID = blockNo;
            leftN->hashValue = SHA256(strBlock);
            levels++;
        }else
        {
            parentN = root;
            int tempN = blockNo;
            if(blockNo % 2)
            {
                cout << "2: blockNo: " << blockNo << endl;
                for(int i = levels-1 ; i >= 0 ; i--)
                {
                    if(tempN < pow(2, i)) // Go left
                        parentN = parentN->left;
                    else
                    {
                        tempN -= pow(2, i);
                        parentN = parentN->right;
                    }
                }

                leftN = parentN;
                leftN->blockID = blockNo;
                leftN->hashValue = SHA256(strBlock);
            }else
            {
                cout << "3: blockNo: " << blockNo << endl;
                int i = levels;
                for( ; i >= 0 ; i--)
                {
                    if(tempN < pow(2, i-1)) // Go left
                        if(parentN->left)
                            parentN = parentN->left;
                        else
                            break;
                    else
                    {
                        tempN -= pow(2, i-1);
                        if(parentN->right)
                            parentN = parentN->right;
                        else
                            break;
                    }
                }

                // Now add the required part of the path:
                while(i > 0)
                {
                    leftN = new Node;
                    leftN->blockID = -1;
                    leftN->value = leftN->hashValue = "";
                    leftN->left = leftN->right = nullptr;

                    rightN = new Node;
                    rightN->blockID = -1;
                    rightN->value = "";
                    rightN->hashValue = SHA256("NULL");
                    rightN->left = rightN->right = nullptr;

                    parentN->left = leftN;
                    parentN->right = rightN;
                    leftN->parent = rightN->parent = parentN;
                    parentN = leftN;
                    i--;
                }

                leftN->blockID = blockNo;
                leftN->hashValue = SHA256(strBlock);
            }
        }

        // Now update the hash values from buttom up.
        UpdateHash(leftN);
        return false;
    }

    bool ReadBlock(int n)
    {
        if(n > blockNo)
        {
            cout << "Not found!" << endl;
            return false;
        }

        int tempN = n;
        Node* tree = root;
        for(int i = levels ; i >= 0 ; i--)
        {
            //cout << "i: " << i << "\ttree->blockID:" << tree->blockID << endl;
            if(tempN < pow(2, i-1)) // Go left
            {
                if(tree->left)
                    tree = tree->left;
                else
                {
                    cout << "Found: " << tree->hashValue << endl;
                    return true;
                }
            }else
            {
                tempN -= pow(2, i-1);
                if(tree->right)
                    tree = tree->right;
                else
                {
                    cout << "Found: " << tree->hashValue << endl;
                    return true;
                }
            }
        }

        return false;
    }

    // When a block is requested, find it, and return it with a proof of membership.
    string ProveBlock(int n)
    {
        string proof("");
        if(n > blockNo)
        {
            cout << "Not found!" << endl;
            return proof;
        }

        int tempN = n;
        Node* tree = root;
        for(int i = levels ; i >= 0 ; i--)
        {
            if(tempN < pow(2, i-1)) // Go left
            {
                if(tree->left)
                    tree = tree->left;
                else
                    cout << "Found: " << tree->hashValue << endl;
            }else
            {
                tempN -= pow(2, i-1);
                if(tree->right)
                    tree = tree->right;
                else
                    cout << "Found: " << tree->hashValue << endl;
            }
        }

        // Now prepare the proof:
        bool bFirst = true;
        Node *leftN = tree, *parentN = leftN->parent, *rightN = nullptr;
        while(parentN)
        {
            if(parentN->left == leftN)
            {
                rightN = parentN->right;
                if(bFirst)
                {
                    proof += "L:";
                    proof += leftN->value;
                    bFirst = false;
                }
                
                proof += "R:";
                proof += rightN->hashValue;
            }else
            {
                rightN = leftN;
                leftN = parentN->left;
                if(bFirst)
                {
                    proof += "R:";
                    proof += rightN->value;
                    bFirst = false;
                }

                proof += "L:";
                proof += leftN->hashValue;
            }

            leftN = parentN;
            parentN = parentN->parent;
        }
        
        return proof;
    }
    
    // Verify if the proof coming from the server is correct that means
    // whether of not the returned block is authentic.
    bool Verify(string proof)
    {
		string info(""), strHash(""), strTemp("");
        int index = 0, n = proof.length();
		// Read the first two characters
		info = proof.substr(0, 2);
		index = proof.find((info == "L:") ? "R:" : "L:", 2);
		strTemp = proof.substr(2, (index == string::npos) ? (n-2) : (index-2));
//        cout << "\nData: " << strTemp << endl << endl;
		strHash = SHA256(strTemp);
//        cout << "Hash: " << strHash << endl;

		while (index < n)
		{
			info = proof.substr(index, 2);
			index += 2;
			strTemp = proof.substr(index, HASHSIZE);
//            cout << "strTemp: " << strTemp << endl;
			if (info == "L:")
				strHash = SHA256(strTemp + strHash);
			else
				strHash = SHA256(strHash + strTemp);
			index += HASHSIZE;
		}

		if(strHash == root->hashValue)
            cout << "\n\n\t\tVerified!!!" << endl << endl;
        else
            cout << "\n\n\t\tNot Verified!!!" << endl << endl;
		return (strHash == root->hashValue);
    }
};

bool menu(MerkleTree& T)
{
    cout << endl << endl << "\tA)dd a new block." << endl;
    cout << "\tR)equest a block." << endl;
    cout << "\tV)erify the proof." << endl;
    cout << "\tT)raverse the tree." << endl;
    cout << "\tQ)uit." << endl;
    cout << endl << "\tEnter your command: ";

    string strBlock("");
    int nBlock = -1;
    char ch = ' ';
    cin.get(ch);
    while(ch == 10)
        cin.get(ch);
    switch(ch)
    {
        case 'a':
        case 'A':
            cout << "\n\tEnter new block text: ";
            cin >> strBlock;
            T.Append(strBlock);
            return true;
        case 'v':
        case 'V':
            T.Verify(strResult);
            return true;
        case 't':
        case 'T':
            T.PrintTree();
            return true;
        case 'r':
        case 'R':
            cout << "\n\tEnter block no: ";
            cin >> nBlock;
            while(nBlock != -1)
            {
                strResult = T.ProveBlock(nBlock);
                cout << strResult << endl;
                cout << "\n\tEnter block no: ";
                cin >> nBlock;
            }
            return true;
        case 'q':
        case 'Q':
            return false;
    }

    return false;
}

int main()
{
    MerkleTree T(70);     // Give the block size (here it is 70 bytes).
    T.Build("inp.txt");   // Give you input file name.
    while(menu(T))
        ;
    return 0;
}
