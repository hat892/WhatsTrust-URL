package trust_system_lib;


import core_lib.*;
import java.io.IOException;
import java.util.*;


/**
 * The TnaSlTM class conforms to the TrustAlg interface and implements the
 * 'Trust Network Analysis with Subjective Logic' approach of Josang et. al.
 */
public class Maimona implements TrustAlg{
	
	// ************************** PRIVATE FIELDS *****************************

	/**
	 * The Network which this TNA-SLMaimona is managing.
	 */
	private Network nw;
        private int random_size; 
        private int services;
        private int[][] friends_array; // who is friend to who.
        private int[][] size; // The size of this array is n × 1, row number 5 means user number 5, row number 8 has value number 3 means that user number 8 has 3 firends
        private Opinion[][] global_reputation; // global_reputation is L1.
        private Opinion[][] L2;
        private static int[][]registry_array;
        private int random_friend;
        private int NUM_USERS;
        private int total_services;
        

        
	// *************************** CONSTRUCTORS ******************************

	/**
	 * Construct a TnaSlTM object.
	 * @param nw Network which this EtIncTM will be managing
	 */
	public Maimona(Network nw) throws IOException{
            //Initializing network, some variable and the registry array:
            this.nw = nw;
            NUM_USERS = this.nw.GLOBALS.NUM_USERS;
            services = NUM_USERS/10;
            total_services = services * NUM_USERS;
            friends_array = new int[NUM_USERS][NUM_USERS];
            global_reputation = new Opinion[NUM_USERS][NUM_USERS];
            L2 = new Opinion[NUM_USERS][NUM_USERS];
            registry_array = new int[NUM_USERS][NUM_USERS];
            size = new int[NUM_USERS][1];
            
            //initializing global_reputation matrix:
            for(int h = 0 ; h < this.nw.GLOBALS.NUM_USERS; h++){
                for(int j = 0 ; j < this.nw.GLOBALS.NUM_USERS; j++){
                    if(this.nw.getUser(h).isPreTrusted()){
                        global_reputation[h][j] = new Opinion(0.0, 0.0, 1.0, 1.0);
                        L2[h][j] = new Opinion(0.0, 0.0, 0.0, 0.0);
                        friends_array[h][j] = -1;
                    }
                    else{
                        global_reputation[h][j] = new Opinion(0.0, 0.0, 1.0, 0.5);
                        L2[h][j] = new Opinion(0.0, 0.0, 0.0, 0.0);
                        friends_array[h][j] = -1;
                    }
                }
            }
            //----------------------------------------------------------------------------------------------------------------------------------------------------------

            //for-loop for initializing each array of each node.
            for(int i = 0 ; i < NUM_USERS ; i++){
                random_size = randInt(1, services);  
                size[i][0] = random_size;
                random_friend = randInt(0, NUM_USERS-1);
                while(random_friend == i){
                    random_friend = randInt(0, NUM_USERS-1);
                }
                // Add random users to the friends_array.
                for(int j = 0 ; j < random_size ; j++){
                    
                    if(this.nw.getUser(random_friend).isPreTrusted()){
                        friends_array[i][j] = random_friend;
                        L2[i][j] = new Opinion(0.0, 0.0, 1.0, 1.0);
                    }
                    else{
                        friends_array[i][j] = random_friend;
                        L2[i][j] = new Opinion(0.0, 0.0, 1.0, 0.5);
                    }
                    random_friend++;
                    if (random_friend == i){random_friend++;}
                    if(random_friend >= NUM_USERS){
                        random_friend = random_friend - (NUM_USERS);
                    }
                }// End of --> // Add random users to the created array.
                random_friend = randInt(0, NUM_USERS-1);
            }// End of --> //for-loop for creating an array for each node.
                initializing_registry_array(NUM_USERS, size);
        }// End of --> // TNA-SLight constructor.
        
	// ************************** PUBLIC METHODS *****************************
	
	/**
	 * Interfaced: Text name of this trust algorithm (spaces are okay).
	 */
	public String algName(){	
            return "Maimona";
	}
	
	/**
	 * Interfaced: File extension placed on output files using this algorithm.
	 */
	public String fileExtension(){
		return "Maimona";
	}
	
	/**
	 * Interfaced: Given coordinates of a feedback commitment, update as needed.
	 */
	public void update(Transaction trans){
            int new_row = trans.getRecv();// who evalute.
            int new_vec = trans.getSend();//who recieve evaluation.
            int pos_fbacks = nw.getUserRelation(new_vec, new_row).getPos();
            int neg_fbacks = nw.getUserRelation(new_vec, new_row).getNeg();
            global_reputation[new_row][new_vec].edit(pos_fbacks, neg_fbacks);
            for(int i = 0 ; i < size[new_row][0] ; i++){
                if (new_vec == friends_array[new_row][i]){
                    L2[new_row][i].edit(pos_fbacks, neg_fbacks);
                }
            }
	}
	
	/**
	 * Interfaced: Compute trust, exporting trust values to Network.
	 */
	public void computeTrust(int receiver, int cycle){
            int service_looking_for;
            Opinion max_trust = new Opinion(0.0, 0.0, 0.0, 0.0);
            ArrayList<Integer> providers = new ArrayList<Integer>();// general provider of the service.
            ArrayList<Integer> receiver_friends = new ArrayList<Integer>();// this when FOF have the service.
            ArrayList<Integer> receiver_friends_index = new ArrayList<Integer>();
            ArrayList<Integer> FOF = new ArrayList<Integer>();
            ArrayList<Integer> FOF_index = new ArrayList<Integer>();
            ArrayList<Opinion> discounts_consensuses = new ArrayList<Opinion>();
            Opinion temp_trust = new Opinion(0.0, 0.0, 0.0, 0.0);
            boolean friend_flag = false;
            boolean fof_flag = false;
            int temp = 0;
            
            
            // 1: collect the servers numbers that have the wanted service.
            // store the server number in "providers" arrayList.
            while(providers.isEmpty()){
                service_looking_for = randInt(0, total_services);
                for(int i = 0 ; i < NUM_USERS ; i++){
                    if (i ==  receiver){continue;}
                    for(int j = 0 ; j < size[i][0] ; j++){
                        if (service_looking_for == registry_array[i][j]){
                            providers.add(i);
                        }
                    }
                }
            }

            // 2: If he is a friend, then we must check every element in providers arrayList.
            // take the element with highest trust value.
            for(int i = 0 ; i < size[receiver][0] ; i++){
                for(int j = 0 ; j < providers.size() ; j++)
                if (friends_array[receiver][i] == providers.get(j)){
                    if(friend_flag == false){friend_flag = true;}
                    if (L2[receiver][i].expectedValue() >= max_trust.expectedValue()){
                        max_trust = L2[receiver][i];
                        temp = providers.get(j);
                    }
                }
            }
            if (friend_flag == true){
            Relation rel1 = this.nw.getUserRelation(temp, receiver);
            rel1.setTrust(max_trust.expectedValue());
            }
            
            
            //3: If he is not a friend, we have to check friends of each provider friend.
            // Warning for the writer: you have to check this code again!.
            if (friend_flag != true){
                for(int h = 0 ; h < providers.size() ; h++){//providers_index
                    for(int i = 0 ; i < size[receiver][0] ; i++){//receiver_f_index
                        for(int j = 0 ; j < size[friends_array[receiver][i]][0] ; j++){//receiver_fof_index
                            if(providers.get(h) == friends_array[friends_array[receiver][i]][j] && friends_array[friends_array[receiver][i]][j] != receiver){
                                if(fof_flag == false){fof_flag = true;}
                                if(L2[friends_array[receiver][i]][j].expectedValue() > max_trust.expectedValue()){
                                    max_trust = L2[friends_array[receiver][i]][j];
                                    receiver_friends.add(friends_array[receiver][i]);
                                    receiver_friends_index.add(i);
                                    FOF.add(friends_array[friends_array[receiver][i]][j]);
                                    FOF_index.add(j);
                                }
                            }
                        }
                        max_trust = new Opinion(0.0, 0.0, 0.0, 0.0);
                    }
                }
                
                if (!FOF.isEmpty()){
                    for(int l = 0 ; l < FOF_index.size() ; l++){
                        discounts_consensuses.add(L2[receiver][receiver_friends_index.get(l)].discount(L2[receiver_friends_index.get(l)][FOF_index.get(l)]));
                    }
                    
                    temp_trust = discounts_consensuses.get(0);
                    for(int k = 0 ; k < providers.size() ; k++){
                        for(int m = 1 ; m < discounts_consensuses.size() ; m++){
                            if (providers.get(k) == FOF.get(m)){
                                temp_trust = temp_trust.consensus(discounts_consensuses.get(m));
                            }
                        }
                        if (temp_trust.expectedValue() >= max_trust.expectedValue()){
                            max_trust = temp_trust;
                            temp = providers.get(k);
                        }
                    }
                    
                    friends_array[receiver][size[receiver][0]] = temp;
                    if (this.nw.getUser(temp).isPreTrusted()){
                        L2[receiver][size[receiver][0]] = new Opinion (0.0, 0.0, 1.0, 1.0);
                    }else{
                        L2[receiver][size[receiver][0]] = new Opinion (0.0, 0.0, 1.0, 0.5);
                    }
                    size[receiver][0]++;
                    Relation rel2 = this.nw.getUserRelation(temp, receiver);
                    rel2.setTrust(max_trust.expectedValue());    
                }
            }
                      
            if(fof_flag != true && friend_flag != true){
                
                int i;
                temp_trust = null;
                for(int h = 0 ; h < providers.size() ; h++){
                    for( i = 0 ; i < NUM_USERS ; i++){
                        for(int j = 0 ; j < size[i][0] ; j++){
                            if (friends_array[i][j] == providers.get(h)){
                                if (temp_trust == null){
                                    temp_trust = L2[i][j];
                                }else{
                                    temp_trust = temp_trust.consensus(L2[i][j]);
                                }
                                
                            }
                        }
                    }
                    if (temp_trust != null){
                    if (temp_trust.expectedValue() >= max_trust.expectedValue()){
                        max_trust = temp_trust;
                        temp = i-1;
                        temp_trust = null;
                    }
                }
                }

                if (temp_trust != null){
                friends_array[receiver][size[receiver][0]] = temp;
                if (this.nw.getUser(temp).isPreTrusted()){
                    L2[receiver][size[receiver][0]] = new Opinion (0.0, 0.0, 1.0, 1.0);
                }else{
                    L2[receiver][size[receiver][0]] = new Opinion (0.0, 0.0, 1.0, 0.5);
                }
                size[receiver][0]++;
                Relation rel = this.nw.getUserRelation(temp, receiver);
                rel.setTrust(max_trust.expectedValue());
                }
                
                
            }//fof flag            
        }

	// ************************** PRIVATE METHODS ****************************
        
            // generates random numbers.
            private static int randInt(int min, int max) {
                Random rand = new Random();
                int randomNum = rand.nextInt((max - min) + 1) + min;
                return randomNum;
            }
            
            public static void initializing_registry_array( int nodes, int size[][]){
                int temp = (nodes/10 * nodes);  
                int service = randInt(0, temp);
                  for(int i = 0 ; i < nodes ; i++){
                      for(int j = 0 ; j < size[i][0] ; j++){
                          registry_array[i][j] = service;                          
                          service ++;
                          if (service > temp){
                              service = service - temp;
                          }
                      }
                      service = randInt(1, temp);
                  }
            }
            
            
            
            
}
