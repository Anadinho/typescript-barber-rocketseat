import {Router} from 'express';
import { getCustomRepository } from 'typeorm';
import {parseISO} from 'date-fns';
import AppointmentsRepository from '../repositories/AppointmentsRepository';
import CreateAppointmentService from '../services/CreateAppointmentService';
import Appointment from '../models/Appointment';
import ensureAuthenticated from '../middlewares/ensureAuthenticated';

const appointmentsRouter = Router();


appointmentsRouter.use(ensureAuthenticated);

// exemplo caso queria adicionar em uma rota especifica appointmentsRouter.get('/', ensureAuthenticated,  async (request, response)

appointmentsRouter.get('/',  async (request, response) =>{
  // console.log(request.user);

  const appointmentsRepository=getCustomRepository(AppointmentsRepository);
  const appointments = await appointmentsRepository.find();

  return response.json(appointments);
});

appointmentsRouter.post('/', async (request,response) => {
  try {
    const{provider_id, date}= request.body;

    const parseDate = parseISO(date);

    const createAppointment = new CreateAppointmentService();

    const appointment = await createAppointment.execute({
      date:parseDate,
      provider_id,
    });

    return response.json(appointment);

  } catch (err) {
    return response.status(400).json({error: err.message});

  }
})

export default appointmentsRouter;
