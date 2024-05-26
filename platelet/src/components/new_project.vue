<script setup>
import { invoke } from "@tauri-apps/api";
import { ref } from "vue";
import { open } from '@tauri-apps/api/dialog';

const name = ref("");
const artery_path = ref("No File Selected");

async function pick_folder() {
  // Open a dialog
  const file = await open({
    multiple: false,
    directory: true,
  });
  if (file) {
    artery_path.value = file;
  }
}


async function create_project() {
    await invoke("create_new_project", {projectName: name.value, arteryPath: artery_path.value}).catch((error) => console.error(error));
}
</script>

<template>
    <form class="row" @submit.prevent="create_project">
      <div id=""wrapper>
        <input id="projet-name" v-model="name" placeholder="Enter your project name" />

            <button type="button" @click="pick_folder"> pick artery folder </button>
            <p> {{ artery_path }} </p>
        <button type="submit">Create Project</button>
      </div>


    </form>

</template>

<style scoped>
        #wrapper{
            padding: 0;
            margin: 0;
            width: 100%;
            height: 100%;
        }
        #wrapper input {
          display: block;
        }
        #wrapper button {
          display: block;
        }
        #wrapper p {
          display: block;
        }
</style>