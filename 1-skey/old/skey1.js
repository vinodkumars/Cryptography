/*
  CS255 - Winter 2014
  Assignment 1: S/KEY Authentication
  Starter Code Version: 1.0

  SUNet ID #1:
  SUNet ID #2:

  Step 1: Find a project partner and add your SUNet IDs above.
  Step 2: Implement `initialize`, `advance`, `save`, and `load` in `pebble_chain`.
  Step 3: Answer the questions below.
  Step 4: See Piazza for submission instructions.
*/

/* 1. Briefly describe your implementation and its design choices. (e.g. What algorithm did you use? How did you structure your code? Did you do something interesting in \texttt{save}/\texttt{load}? If it's not obvious, justify the space/time used by your implementation.)
// TODO: Answer here (a few sentences).
*/

/* 2. If you were designing an authentication mechanism for a hot new startup that wants to protect its users, how would you decide whether/where to use S/KEY?
// TODO: Answer here (a few sentences).
*/

/* 3. (Will not affect your grade:) How long did you spend on this project?
// TODO: Answer here (just a number).
*/

/* 4. (Optional:) Do you have any comments or suggestions for improving the assignment?
// TODO: Answer here (optional).
*/


/********* External Imports and Convenience Functions ********/


"use strict"; // Makes it easier to catch errors.

var sjcl = require("./lib/sjcl");
var hash = sjcl.hash.sha256.hash; // Hashes a string or bitArray to a bitArray.
var is_equal = sjcl.bitArray.equal; // Compares two bitArrays.
var hex = sjcl.codec.hex.fromBits; // Converts a bitArray to a hex string.

var pow2 = Math.pow.bind(this, 2); // Calculates 2 to a given power.
var log2 = function(x) {return Math.log(x) / Math.log(2);} // Calculates log base 2.


/******** Naive Hash Chain Implementation ********/


function naive_chain() {

  var chain = {
    state: null
  };

  chain.initialize = function(num_iterations, seed) {
    chain.state = {
      position: 0,
      num_iterations: num_iterations,
      start: hash(seed)
    }

    var initial = chain.state.start;
    for (var i = 0; i < chain.state.num_iterations; i++) {
      initial = hash(initial);
    }

    return initial;
  }

  chain.advance = function() {
    if (chain.state.position + 1 > chain.state.num_iterations) {
      return null;
    }

    var value = chain.state.start;
    for (var i = 1; i < chain.state.num_iterations - chain.state.position; i++) {
      value = hash(value);
    }
    chain.state.position += 1;
    return value;
  }

  // Returns a string.
  chain.save = function() {
    return JSON.stringify(chain.state);
  }

  // Loads a string.
  chain.load = function(str_data) {
    chain.state = JSON.parse(str_data);
  }

  return chain;
}

/******** Pebble-Based Hash Chain Implementation (Jakobsson's algorithm) ********/

function pebble_chain() {

  var chain = {
    state: null
  };

  chain.initialize = function(num_iterations, seed) {
    chain.state = {
      position: 0,
      num_iterations: num_iterations,
      pebbleQueue: [],
      hashOfSeed: hash(seed),
      hashCount: 0
    }

    //Exit if num_iterations is <=0
    if(num_iterations<=0)
    {
        return null;
    }
    //Allocating log2(num_iterations) pebbles
    var pebbleCountToAllocate=log2(num_iterations);
    //A variable to iterate through the hash values in the hash chain in order to find the pebble's values.
    var hashChainNode = {
        position: num_iterations,
        value: chain.state.hashOfSeed
    }
    for(var i=pebbleCountToAllocate;i>0;i--)
    {
        //Initiating the values of the pebbles
        var newPebble = {
          position: pow2(i),
          destination: pow2(i),
          value:null
        }
        //Finding the pebbles values
        while(hashChainNode.position!==newPebble.position)
        {
            hashChainNode.position--;
            hashChainNode.value=hash(hashChainNode.value);
        }
        newPebble.value=hashChainNode.value;
        //Placing the pebble in the destination-prioritised queue
        chain.enqueue(newPebble);
    }
    //Finding the initial value to return
    while(hashChainNode.position!==0)
    {
        hashChainNode.position--;
        hashChainNode.value=hash(hashChainNode.value);
    }
    return hashChainNode.value;
  }

  chain.enqueue = function(newElement) {
    //Create first queue element if queue is empty
    if(chain.isPebbleQueueEmpty())
    {
      chain.state.pebbleQueue.push(newElement);
    }
    else
    {
      //The queue has smaller destination elements on the front.
      var i=0;
      //Finding the new elements place in the queue based on destination
      while(i<chain.state.pebbleQueue.length && chain.state.pebbleQueue[i].destination<newElement.destination)
      {
        i++;
      }
      chain.state.pebbleQueue.splice(i,0,newElement);
    }
  }

  chain.dequeue=function(){
    //Dequeueing the first element
    return chain.state.pebbleQueue.shift();
  }

  chain.isPebbleQueueEmpty=function(){
    //Returns true if the queue is empty
    return chain.state.pebbleQueue.length===0;
  }

  chain.advance = function() {
    chain.state.position++;
    //Check if reached the end of the chain
    if (chain.state.position > chain.state.num_iterations)
    {
        return null;
    }

    //Special casing when number of iterations is 1 as there would be no pebbles to operate.
    if(chain.state.num_iterations===1)
    {
        return chain.state.hashOfSeed;
    }

    //Moving the pebbles to its destination
    for(var i=0;i<chain.state.pebbleQueue.length;i++)
    {
        if(chain.state.pebbleQueue[i].position!==chain.state.pebbleQueue[i].destination)
        {
            chain.state.pebbleQueue[i].position-=2;
            chain.state.pebbleQueue[i].value=hash(hash(chain.state.pebbleQueue[i].value));
            //hashCount is just a counter to find out the amortised cost
            chain.state.hashCount+=2;
        }
    }

    if(chain.state.position%2===1)
    {
        //hashCount is just a counter to find out the amortised cost
        chain.state.hashCount+=1;
        //If position is odd, return the hash of the value of the pebble whose destination is the smallest
        return hash(chain.state.pebbleQueue[0].value);
    }
    else
    {
        var pebble=chain.dequeue();
        //If position is even, return the value of the pebble whose destination is the smallest
        var returnValue=pebble.value;
        // Calculating type
        var i = 1;
        var type = pow2(i);
        while (Math.floor(pebble.position / type) % 2 !== 1)
        {
            type = pow2(++i);
        }
        //Calculate the new destination of the pebble
        pebble.destination=pebble.position+(2*type);
        //If the new destination lies within the hash chain, calculate the resst of the values
        if(pebble.destination<=chain.state.num_iterations)
        {
            pebble.position=pebble.position+(3*type);
            //Finding the pebble's value from an existing pebble whose position match
            for(var i=0;i<chain.state.pebbleQueue.length;i++)
            {
                if(chain.state.pebbleQueue[i].position===pebble.position)
                {
                    pebble.value=chain.state.pebbleQueue[i].value;
                    break;
                }
            }
            //Place the pebbles in the destination-prioritised queue
            chain.enqueue(pebble);
        }
        return returnValue;
    }
  }

  // Returns a string.
  chain.save = function() {
    return JSON.stringify(chain.state);
  }

  // Loads a string.
  chain.load = function(str_data) {
    chain.state = JSON.parse(str_data);
  }

  return chain;
}

/********* Export functions for testing. ********/


module.exports.naive_chain = naive_chain;
module.exports.pebble_chain = pebble_chain;


/********* End of Original File ********/

